# attest-verifier

An independent TypeScript implementation of an attest verifier, covering both published profiles: [v0.1](../../docs/spec/attest-v0.1.md) (Ed25519) and [v0.2](../../docs/spec/attest-v0.2.md) (hybrid Ed25519 + ML-DSA-65, plus Stage 2 transparency and anchoring evidence, Stage 3's issuer-mediated transfer, Stage 4's preservation pledge, §19's time-boxed compromise rescue, and §20's publisher authority). It checks a signed attest receipt envelope and reports its signature, schema, trust, revocation, and buyer-binding status — it does not issue, sign, or mutate receipts, manifests, or revocation records. Issuance is the Python reference implementation's job (`attest` package, repo root); this package only ever reads.

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
  options?: VerifyTransparencyOptions,   // { transparency?, logKeys?, anchorPolicy?, compromiseView? } — v0.2 Stage 2
): VerificationResult

export function isOk(r: VerificationResult): boolean // signature=valid && schema=valid && revocation!=='revoked' && errors.length===0
```

`maxRevocationRecords` bounds the untrusted `revocationView` (default 10000); a view larger than the cap is not evaluated and fails closed (an `errors` entry, so `isOk()` is `false`) for a revocable receipt, or warns for an irrevocable one.

`options` is how v0.2 Stage 2 evidence enters: `transparency` (the inclusion evidence accompanying the receipt), `logKeys` (the log keys you pin, in your own trust store — never taken from the bundle), and `anchorPolicy` (including the CRQC horizon). Omit it entirely and verification behaves exactly as before, offline and log-free; supply it and the result additionally carries `transparency` / `corroboration`, which never upgrade the `trust` verdict.

`compromiseView` is the v0.2 §19 channel for key-manifest compromise declarations. Each claim is `{ manifest, evidence }`, where `manifest` is the issuer key manifest declaring the signing `kid` compromised and `evidence` is that manifest's transparency proof. Authenticated declarations make `compromised` absorbing even if the trusted manifest later re-lists the key as active; a Stage-2-capable verifier can still accept a receipt whose own `transparency` claim proves the receipt was anchored strictly before the earliest anchored compromise declaration. A declaration with no anchored time cannot invalidate an anchored receipt, and a receipt with no anchored receipt claim is not rescued.

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

This runs `test/conformance.test.ts`, which discovers every leaf directory under [`docs/spec/vectors/`](../../docs/spec/vectors/) (any directory containing an `expected.json`, walked recursively so multi-part vectors like `07-unicode-canon/a-...` and `17-binding-proven/b-...` are included) and routes each leaf to the surface its files name. A leaf belongs to exactly one of four:

- **`verify()`**, for every leaf naming none of the three files below: envelope bytes, trust store, revocation view, disclosure, and the evidence channels of Stage 2, Stage 3, Stage 4, §19 and §20. Four of those channels are files a leaf opts into — `transfer-view.json` (v0.2 §17), `grant-view.json` (v0.2 §18.4, the sunset-grant evidence object `{grant[, later_grants][, declarations][, anchor]}`), `compromise-view.json` (v0.2 §19, key-manifest compromise declarations), and `authority-view.json` (v0.2 §20, publisher authorization evidence). Supplying `grant-view.json` *is* Stage 4's capability gate: a leaf without it gets `grant`/`grant_trust` at `not_checked`, which is exactly what group 37's own v0.1 negative control pins.
- **`auditChain`** (v0.2 §17.5), for a leaf carrying `chain.json`.
- **`evaluateActivationWitnessQuorum`** (v0.2 §11.4), for a leaf carrying `witness-quorum.json`.
- **`verifyRedemption`** (v0.2 §18.7), for a leaf carrying `redemption.json` — four leaves, the only per-surface count a guard test pins. The question these ask involves no receipt and no grant document at all, only whether a holder's audience-bound proof is good for *this* custodian, so they carry no envelope or trust store; their result shape is a single `{"verified": bool}`, and every negative one must come back `false` rather than throw.

`verify()` leaves are matched against `expected.json` with exact match on `signature`/`schema`/`trust`; exact match on `revocation`/`binding`/`transparency`/`corroboration`/`manifest_freshness`/`grant`/`grant_trust`/`publisher_authority`/`publisher_authority_trust`/`ok` when the key is present; exact list match on `errors`/`warnings` when present; and substring containment for `errors_contains`/`warnings_contains`. The last three surfaces have result shapes of their own. These are the same match rules and the same routing the Python reference implementation's `tests/test_vectors.py` applies to the identical vector files. Two guard tests protect the discovery itself: one counts the corpus on disk and asserts discovery finds exactly that many, so a loader bug that silently skips vectors fails loudly instead of passing on a truncated set — it was a constant floor until a review observed that a floor stops catching anything once the corpus grows past it; the other asserts the four surfaces partition the corpus exactly — their sizes sum to the whole, and the redemption surface holds exactly 4 — so a leaf shipping two surface files, or a fifth surface nobody excluded, cannot vanish from the gate. The individual shares are deliberately not quoted here: they move whenever the corpus grows, pinning them would fail the suite on every addition, and a number no test defends is a number that goes stale without anyone noticing. The test is the record; run it to see today's split.

**Passing every vector in `docs/spec/vectors/` — reproducing every `expected.json` exactly, with zero vectors skipped — is the definition of attest conformance for this implementation.**

This verifier implements both published profiles: v0.1 (Ed25519) and v0.2, which adds the hybrid Ed25519 + ML-DSA-65 signature profile, the Stage 2 transparency/anchoring evidence, Stage 3's issuer-mediated transfer and chain of title, Stage 4's preservation pledge, §19's time-boxed compromise rescue, and §20's publisher authority — see `src/mldsa.ts`, `src/transparency.ts`, `src/tlog.ts`, `src/anchor.ts`, `src/witness.ts`, `src/transfer.ts`, `src/grant.ts` and `src/authority.ts`. Hybrid verification is AND semantics: both signature legs must verify or the receipt is rejected. Run `npm test` for the full suite (parser, canonicalization, Ed25519, manifests, revocation, commitment, schema, and this conformance runner together).
