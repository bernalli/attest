// The TypeScript half of a DELIBERATE two-core divergence (v0.2 §18.4).
//
// A signed revocation record carried as a class instance with the record's
// members as its OWN data is HONOURED by this core and set aside by the Python
// one. Both are conforming: §18.4 requires own-data reconstruction. Python
// preserves a container subtype's base data but cannot represent this
// non-container instance; TypeScript reconstructs its enumerable own
// data-property descriptors.
//
// THIS FILE IS ONE HALF OF A PAIR. The other is
// `tests/test_class_instance_divergence.py`. Changes to the specified behaviour
// require a joint revision of both tests and the normative paragraph.
//
// The two defences divide the work, and neither covers the other. The text
// fingerprint defends the TEXT: it makes an edit to the paragraph visible
// rather than silent, and no digest can stop one. Independent review defends
// the CHRONOLOGY: an author who changes a core AND its own expectation in one
// diff passes every check here, by construction, because the oracle moved with
// the code. A diff that touches a core and its expected outcome together is
// therefore a change of MEANING, to be read as such — not a test being kept in
// sync.
//
// Each test asserts the REASON, not only the outcome: an outcome-only test
// stays green the day the same outcome starts arriving from a different path.
import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { materializeValue } from '../src/canon.js'
import { canonicalBytes, isOk, verify } from '../src/index.js'
import type { JsonObject, JsonValue, TrustStore } from '../src/index.js'
import {
  buildKeyManifest,
  hybridSigner,
  keyEntry,
  parse,
  signBlock,
} from './helpers/grant-builder.js'
import { store } from './helpers/trust.js'

const enc = new TextEncoder()
const dec = new TextDecoder()
const ISSUER = 'store.example.com'
const ISSUER_KID = `${ISSUER}/keys/2026-01#ed25519-1`
const VALID_FROM = '2026-01-01T00:00:00Z'
const RECEIPT_ISSUED_AT = '2026-07-02T14:30:00Z'
const REVOKED_AT = '2026-07-03T00:00:00Z'
const RECEIPT_ID = '01J1V5B4M9Z8QWERTY12345678'
const ISSUER_KEYS = hybridSigner(81)
const HOLDER_PUB = ed25519.getPublicKey(new Uint8Array(32).fill(85))
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url')

const REPO_ROOT = join(import.meta.dirname, '..', '..', '..')
const SPEC = join(REPO_ROOT, 'docs', 'spec', 'attest-v0.2.md')
const DECLARATION = '**The cost is not paid identically by the two cores (normative).**'
const PY_TWIN = 'tests/test_class_instance_divergence.py'

const ISSUER_MANIFEST = buildKeyManifest(
  ISSUER,
  1,
  VALID_FROM,
  [keyEntry(ISSUER_KID, ISSUER_KEYS, VALID_FROM, { validTo: null, status: 'active' })],
  ISSUER_KEYS,
  ISSUER_KID,
)

function payload(revocability = 'policy'): JsonObject {
  return parse({
    attest_version: '0.2',
    receipt_id: RECEIPT_ID,
    issued_at: RECEIPT_ISSUED_AT,
    supersedes: null,
    issuer: { id: ISSUER, display_name: 'Example Store' },
    buyer: {
      commitment: b64u(new Uint8Array(32)),
      identifier_type: 'issuer-account',
      pubkey: b64u(HOLDER_PUB),
    },
    work: {
      title: 'Example Game',
      publisher: 'Example Publisher',
      identifiers: { issuer_sku: 'EXG-001' },
      artifact_series: 'store.example.com/works/EXG-001',
    },
    license: {
      grant: 'perpetual',
      revocability,
      revocation_window_days: 30,
      transferable: false,
      drm: 'drm-free',
      terms_uri: 'https://store.example.com/license',
      legal_text_sha256: 'a'.repeat(64),
    },
    survivability: {
      redownload_right: true,
      end_of_life: 'none',
      eol_commitment_uri: null,
      eol_commitment_sha256: null,
    },
  })
}

function envelopeBytes(p: JsonObject): Uint8Array {
  const bytes = canonicalBytes(p)
  return enc.encode(
    JSON.stringify({
      payload: JSON.parse(dec.decode(bytes)),
      signatures: [
        { kid: ISSUER_KID, alg: 'Ed25519', sig: b64u(ed25519.sign(bytes, ISSUER_KEYS.edSeed)) },
        {
          kid: ISSUER_KID,
          alg: 'ML-DSA-65',
          sig: b64u(ml_dsa65.sign(bytes, ISSUER_KEYS.mldsaSecret!)),
        },
      ],
    }),
  )
}

const trustStore = (): TrustStore =>
  store({
    manifests: { [ISSUER]: ISSUER_MANIFEST },
    provenance: { [ISSUER]: 'tls' },
  })

/** A GENUINELY SIGNED revocation record for this receipt. */
function signedRecord(): Record<string, unknown> {
  const body = { receipt_id: RECEIPT_ID, status: 'revoked', revoked_at: REVOKED_AT }
  return { ...body, signature: signBlock(canonicalBytes(parse(body)), ISSUER_KEYS, ISSUER_KID) }
}

/** Members as OWN DATA properties — an ORM row, a model object. */
class OrmRow {
  constructor(record: Record<string, unknown>) {
    Object.assign(this, record)
  }
}

/** Members exposed as prototype GETTERS — accessor, not data. */
class GetterRow {
  #record: Record<string, unknown>
  constructor(record: Record<string, unknown>) {
    this.#record = record
  }
  get receipt_id() {
    return this.#record.receipt_id
  }
  get status() {
    return this.#record.status
  }
  get revoked_at() {
    return this.#record.revoked_at
  }
  get signature() {
    return this.#record.signature
  }
}

// Positional signature, as the core exposes it: the revocation view is the
// third argument. The cast is the point of the test — the whole subject is a
// value the declared type does not admit but a real caller can pass.
const verifyWith = (record: unknown, revocability = 'policy') =>
  verify(
    envelopeBytes(payload(revocability)),
    trustStore(),
    [record] as unknown as JsonValue[],
    null,
    undefined,
    {} as never,
  )

describe('class-instance divergence (v0.2 §18.4, deliberate)', () => {
  it('honours a plain record — the control', () => {
    // Without this, the divergence test could pass because the fixture never
    // revoked anything.
    const result = verifyWith(signedRecord())
    expect(result.revocation).toBe('revoked')
    expect(isOk(result)).toBe(false)
  })

  it('honours a class instance carrying the record as own data', () => {
    // The Python twin asserts `unknown` / ok true for this same shape.
    const result = verifyWith(new OrmRow(signedRecord()))
    expect(result.revocation).toBe('revoked')
    expect(isOk(result)).toBe(false)
  })

  it.each(['receipt_id', 'status', 'revoked_at', 'signature'])(
    'omits %s unless it is enumerable own data, and refuses it whole as an accessor',
    (member) => {
      const record = signedRecord()
      const expected = { ...record }
      delete expected[member]

      for (const kind of ['own-accessor', 'inherited-data', 'non-enumerable'] as const) {
        let reads = 0
        const row = new OrmRow(expected)
        const getter = () => {
          reads++
          return record[member]
        }
        if (kind === 'inherited-data') {
          Object.setPrototypeOf(row, { [member]: record[member] })
          expect(Object.getOwnPropertyDescriptor(row, member)).toBeUndefined()
          const inherited = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(row), member)
          expect(inherited).toBeDefined()
          expect(inherited!.value).toBe(record[member])
        } else {
          Object.defineProperty(row, member, kind === 'own-accessor'
            ? { enumerable: true, get: getter }
            : { enumerable: false, value: record[member] })
          const descriptor = Object.getOwnPropertyDescriptor(row, member)
          expect(descriptor).toBeDefined()
          if (kind === 'own-accessor') {
            expect(descriptor!.get).toBe(getter)
            expect('value' in descriptor!).toBe(false)
            expect(descriptor!.enumerable).toBe(true)
          } else {
            expect(descriptor!.value).toBe(record[member])
            expect(descriptor!.enumerable).toBe(false)
          }
        }

        const admitted = materializeValue(row)
        expect(reads, 'OWN_ACCESSOR_MUST_NOT_EXECUTE').toBe(0)

        if (kind === 'own-accessor') {
          // An accessor is REFUSED, not skipped (canon.ts's `ownDataCopy`
          // doc comment, "data or code decides first"): a reconstruction
          // that silently drops the key `row` carries is not `row`, so the
          // WHOLE unit is set aside rather than admitted with that one
          // member missing. The two data-property kinds below (inherited,
          // non-enumerable) are not code — they are JSON-form decisions —
          // and keep the old "member omitted, rest admitted" outcome; only
          // the accessor case changed. The normative paragraph pinned at
          // the bottom of this file is untouched: its precondition is "all
          // record members as enumerable OWN data", which an accessor does
          // not satisfy, so this refusal sits outside what it governs.
          expect(admitted, 'ADMISSION_MUST_REFUSE_own-accessor_' + member).toBeNull()
        } else {
          expect(admitted, 'ADMISSION_MUST_OMIT_' + kind + '_' + member).toEqual(parse(expected))
        }

        const result = verifyWith(row)
        expect(reads, 'VERIFY_MUST_NOT_EXECUTE_OWN_ACCESSOR').toBe(0)
        expect(result.signature).toBe('valid')
        expect(result.schema).toBe('valid')
        expect(result.errors).toEqual([])
        expect(result.revocation).toBe('unknown')
        expect(isOk(result)).toBe(true)
        expect(result.warnings, 'MATCHING_INCOMPLETE_RECORD_MUST_WARN').toEqual(
          member === 'receipt_id' ? []
            : ["revocation record for '" + RECEIPT_ID + "' failed verification, ignored"],
        )
      }
    },
  )

  it('treats prototype getters as absent members', () => {
    const row = new GetterRow(signedRecord())
    const descriptor = Object.getOwnPropertyDescriptor(GetterRow.prototype, 'status')
    expect(descriptor).toBeDefined()
    expect(typeof descriptor!.get).toBe('function')
    expect('value' in descriptor!).toBe(false)
    expect(Object.getOwnPropertyDescriptor(row, 'status')).toBeUndefined()
    expect(materializeValue(row)).toEqual({})
    const result = verifyWith(row)
    expect(result.revocation).toBe('unknown')
    expect(isOk(result)).toBe(true)
    expect(result.warnings).toEqual([])
  })

  it('honours enumerable own data on a null-prototype object', () => {
    const record = signedRecord()
    const row = Object.assign(Object.create(null), record)
    expect(Object.getPrototypeOf(row)).toBeNull()
    expect(materializeValue(row)).toEqual(parse(record))
    const result = verifyWith(row)
    expect(result.revocation).toBe('revoked')
    expect(isOk(result)).toBe(false)
  })

  it('reads an Array subclass through own indices without invoking its iterator', () => {
    let iterations = 0
    class RecordArray extends Array<JsonValue> {
      override [Symbol.iterator](): ArrayIterator<JsonValue> {
        iterations++
        throw new Error('ARRAY_ITERATOR_MUST_NOT_EXECUTE')
      }
    }
    const view = new RecordArray()
    view.push(new OrmRow(signedRecord()) as unknown as JsonValue)
    const result = verify(
      envelopeBytes(payload()), trustStore(), view, null, undefined, {} as never,
    )
    expect(iterations, 'ARRAY_ITERATOR_MUST_NOT_EXECUTE').toBe(0)
    expect(result.revocation).toBe('revoked')
    expect(isOk(result)).toBe(false)
  })

  it('pins the full normative text together with its Python twin', () => {
    const spec = readFileSync(SPEC, 'utf-8')
    expect(spec).toContain(DECLARATION)
    const paragraph = spec.slice(spec.indexOf(DECLARATION)).split('\n', 1)[0]!
    expect(paragraph).toContain('`revocation: "unknown"`')
    expect(paragraph).toContain('`revocation: "revoked"`')
    expect(paragraph).toContain(PY_TWIN)
    expect(paragraph).toContain('verifiers/ts/test/class-instance-divergence.test.ts')
    expect(
      createHash('sha256').update(paragraph, 'utf8').digest('hex'),
      'NORMATIVE_DIVERGENCE_PARAGRAPH_CHANGED',
    ).toBe('babb9cbc2032f79dedcd8f26ded79f4c351f5737a36424bd518470e46d27e9dc')
  })
  it('admits the record on an irrevocable licence and says so — same ok, opposite reason', () => {
    // Outside the normative paragraph's preconditions, which fix
    // `revocability: "policy"`. Here the licence class decides the outcome
    // (v0.1 §12.2). Both cores leave ok true, so the outcome alone cannot
    // tell them apart: the Python twin reports `unknown` with NO warning,
    // never having admitted the record, while this core admits it,
    // authenticates it, and discards it as irrevocable. The warning is the
    // only observable that says which of the two happened.
    const result = verifyWith(new OrmRow(signedRecord()), 'none')
    expect(result.revocation).toBe('invalid_revocation_ignored')
    expect(isOk(result)).toBe(true)
    // Asserted by CONTENT, not by "the list is non-empty": a different
    // warning would mean a different path reached the same outcome.
    expect(
      result.warnings.some((w) => w.includes('irrevocable')),
      'IRREVOCABLE_DISCARD_MUST_BE_REPORTED',
    ).toBe(true)
  })
})
