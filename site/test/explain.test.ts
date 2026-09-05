import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { explain, explainVerdict, attributeWarning, COMPONENTS, GROUPS } from '../src/explain.js'
import type { Component } from '../src/explain.js'
import type { VerificationResult } from 'attest-verifier'

const KNOWN: Record<Component, string[]> = {
  signature: ['valid', 'invalid'],
  schema: ['valid', 'invalid', 'not_checked'],
  binding: ['proven', 'not_proven', 'not_checked'],
  trust: ['verified', 'unauthenticated_tofu', 'unverified_rotation'],
  revocation: [
    'unknown', 'revoked', 'invalid_revocation_ignored', 'transferred',
    'not_revoked_as_of:2026-01-01T00:00:00Z',
  ],
  grant: ['not_checked', 'none', 'dormant', 'activated', 'invalid_grant_ignored'],
  grant_trust: [
    'not_checked', 'verified', 'unauthenticated_tofu', 'unverified_rotation', 'signer_mismatch',
  ],
  publisher_authority: [
    'not_checked', 'no_publisher_claim', 'self', 'authorized', 'unauthorized', 'unattested',
  ],
  publisher_authority_trust: [
    'not_checked', 'verified', 'unauthenticated_tofu', 'unverified_rotation', 'signer_mismatch',
  ],
  transparency: [
    'not_checked', 'logged', 'equivocation_detected', 'anchored_before:2026-08-26T00:00:00Z',
  ],
  corroboration: ['none', 'logged', 'witnessed'],
  manifest_freshness: ['not_checked', 'verified_as_of:7'],
}

const result = (over: Partial<VerificationResult> = {}): VerificationResult => ({
  signature: 'valid', schema: 'valid', revocation: 'unknown',
  binding: 'not_checked', trust: 'verified',
  transparency: 'not_checked', corroboration: 'none', manifest_freshness: 'not_checked',
  grant: 'not_checked', grant_trust: 'not_checked',
  publisher_authority: 'not_checked', publisher_authority_trust: 'not_checked',
  warnings: [], errors: [],
  ...over,
})

describe('the twelve components', () => {
  it('are exactly the components of the three question groups, in order', () => {
    expect(COMPONENTS).toEqual(GROUPS.flatMap((g) => g.components))
    expect(new Set(COMPONENTS).size).toBe(12)
    expect(GROUPS.map((g) => g.components.length)).toEqual([4, 5, 3])
  })

  it('covers every allowed value of the result contract with real copy', () => {
    for (const component of COMPONENTS) {
      for (const value of KNOWN[component]) {
        const e = explain(component, value)
        expect(e.label.length, `${component}/${value}`).toBeGreaterThan(0)
        // A real sentence, not a stub — and never the generic fallback.
        expect(e.text.length, `${component}/${value}`).toBeGreaterThan(40)
        expect(e.text, `${component}/${value}`).not.toContain('does not have dedicated wording')
      }
    }
  })

  it('assigns honest tones', () => {
    expect(explain('signature', 'valid').tone).toBe('good')
    expect(explain('signature', 'invalid').tone).toBe('bad')
    expect(explain('revocation', 'revoked').tone).toBe('bad')
    expect(explain('revocation', 'transferred').tone).toBe('bad')
    expect(explain('revocation', 'unknown').tone).toBe('neutral')
    expect(explain('trust', 'unauthenticated_tofu').tone).toBe('warn')
    expect(explain('binding', 'proven').tone).toBe('good')
    // Informational by construction (spec §10, §18.5): a component that can
    // never move `ok` must never be painted as a failure of the receipt.
    expect(explain('grant', 'not_checked').tone).toBe('neutral')
    expect(explain('grant', 'dormant').tone).toBe('good')
    expect(explain('grant', 'invalid_grant_ignored').tone).toBe('warn')
    expect(explain('grant_trust', 'signer_mismatch').tone).toBe('warn')
    expect(explain('corroboration', 'none').tone).toBe('neutral')
    // The one hard verdict of the transparency layer (spec §10.3).
    expect(explain('transparency', 'equivocation_detected').tone).toBe('bad')
  })

  it('reads a parametric value’s argument back into the sentence', () => {
    expect(explain('transparency', 'anchored_before:2026-08-26T00:00:00Z').text)
      .toContain('2026-08-26T00:00:00Z')
    expect(explain('manifest_freshness', 'verified_as_of:7').text).toContain('7 entries')
    expect(explain('revocation', 'not_revoked_as_of:2026-01-01T00:00:00Z').text)
      .toContain('2026-01-01T00:00:00Z')
    // A prefix belongs to ONE component: the same suffix under another must
    // not borrow its wording.
    expect(explain('transparency', 'verified_as_of:7').text).toContain('does not have dedicated wording')
  })

  it('never throws on unknown values (future-proof fallback)', () => {
    const e = explain('revocation', 'something_new')
    expect(e.tone).toBe('neutral')
    expect(e.text.length).toBeGreaterThan(0)
  })

  it('explains the verdict', () => {
    expect(explainVerdict(true).tone).toBe('good')
    expect(explainVerdict(false).tone).toBe('bad')
  })
})

// Three things the spec forbids the copy from saying, or requires it to say.
// They are pinned here because they are the difference between a page that
// explains the protocol and a page that overstates it.
describe('the three normative constraints on the copy', () => {
  it('never sells `witnessed` as organizational independence (spec §10.1)', () => {
    const text = explain('corroboration', 'witnessed').text
    expect(text).toMatch(/NOT evidence that/)
    expect(text).toMatch(/independen/i)
    // §10.1: "v1 defines no positive independence certificate or inference rule"
    expect(text).toMatch(/no way to establish independence/i)
  })

  it('reads `verified_as_of:<N>` as a tree size, and not as the key’s state today (spec §10.4)', () => {
    const text = explain('manifest_freshness', 'verified_as_of:12').text
    expect(text).toContain('12 entries')
    expect(text).toMatch(/not seconds/)
    expect(text).toMatch(/nothing about those keys NOW/)
  })

  it('says a `grant_trust` that diverges from `grant` is normal (spec §18.5)', () => {
    const text = explain('grant_trust', 'verified').text
    expect(text).toMatch(/best available value/)
    expect(text).toMatch(/not a contradiction/)
  })

  it('does not repeat the old absolute transparency-rescue claim after spec §19', () => {
    const note = GROUPS.find((group) => group.question === 'Has anyone else seen it?')!.note
    expect(note).toMatch(/except/)
    expect(note).toMatch(/§19/)
    expect(note).not.toMatch(/nothing in this group can rescue an invalid receipt/i)
  })

  // Every input to both binding paths is the issuer's own: the identifier
  // arrives at checkout, the salt is issuer-generated, and `buyer.pubkey` is
  // written into the payload the issuer signs (spec §8). So `proven` reports
  // possession of a secret the issuer recorded and never participation of the
  // buyer, and §11.1 forbids a rendering surface from saying otherwise. The
  // three sentences this pins each used to say otherwise.
  it('never reads binding as who made the purchase (spec §8, §11.1)', () => {
    expect(explain('binding', 'proven').text).toBe(
      'The disclosed identifier and salt reproduce the buyer commitment sealed inside the signed payload: whoever supplied them holds this receipt’s binding secret. Both of those values are the issuer’s own, so that is the whole of what it shows — never that the person named made the purchase (spec §8, §11.1).',
    )

    // `not_proven` says a proof failed, never that the presenter is an impostor.
    expect(explain('binding', 'not_proven').text).toBe(
      'A binding proof was attempted and did not verify: what was supplied does not reproduce the sealed buyer commitment — a wrong identifier, a wrong salt, or the wrong receipt. That is all it reports, and it never says that whoever supplied them is not the buyer (spec §8, §11.1).',
    )

    // `not_checked` says nobody asked — not that the question is "whose is it".
    expect(explain('binding', 'not_checked').text).toBe(
      'Nobody attempted the binding proof — the receipt is genuine either way. Binding reports who holds the secret the issuer sealed into the payload, never who made the purchase. Use the panel above with the receipt’s salt to attempt it (spec §8, §11.1).',
    )

    const authentic = GROUPS.find((group) => group.question === 'Is it authentic?')!.note
    expect(authentic).toMatch(/binding secret the issuer recorded/i)
    expect(authentic).not.toMatch(/whose receipt|belongs to|who bought/i)
  })
})

describe('compromise-cutoff copy', () => {
  it('distinguishes an unrescued compromised key from generic signature failure', () => {
    const text = explain('signature', 'invalid', result({
      signature: 'invalid',
      errors: ['key store.example.com/keys/2025-01#ed25519-1 is compromised'],
    })).text
    expect(text).toMatch(/declared compromised/)
    expect(text).toMatch(/no anchored proof/)
    expect(text).toMatch(/may be genuine/)
  })

  it('explains the after-cutoff invalid-signature zone', () => {
    const text = explain('signature', 'invalid', result({
      signature: 'invalid',
      warnings: ['compromise_rescue_receipt_after_cutoff'],
      errors: ['key store.example.com/keys/2025-01#ed25519-1 is compromised'],
    })).text
    expect(text).toMatch(/not anchored strictly before/i)
    expect(text).toMatch(/compromise/)
    expect(text).toMatch(/Equality is not proof of precedence/)
  })

  it('explains an anchored-before rescue as a timeline proof', () => {
    const text = explain('signature', 'valid', result({
      warnings: ['compromise_rescue_applied'],
    })).text
    expect(text).toMatch(/exact signature/)
    expect(text).toMatch(/strictly before/)
    expect(text).toMatch(/cannot take back/)
    expect(text).toMatch(/v0\.2/)
  })

  it('explains the unanchored-cutoff rescue separately', () => {
    const text = explain('signature', 'valid', result({
      warnings: ['compromise_cutoff_unanchored'],
    })).text
    expect(text).toMatch(/no anchored compromise cutoff was established/)
    expect(text).toMatch(/could not establish one/)
    expect(text).toMatch(/cannot invalidate/)
    // 41r: there the declaration IS anchored; the cutoff dies on §19.3 item 3b.
    expect(text).not.toMatch(/declaration itself carries no anchored time/)
  })

  it('never offers the buyer a TLS fetch that no shipped tool performs', () => {
    // This sentence used to say the attest CLI could fetch the manifest over
    // TLS and reach `verified`. It could not, and still cannot: `verify()`
    // grants `verified` only when the trust store's provenance is `tls`, and
    // both `cli.py` and `bundle.py` set provenance to `bundle` unconditionally
    // while the package ships no HTTP client at all.
    //
    // So the assertion is anchored to the CAPABILITY rather than to today's
    // wording: the premise is checked here, against the reference
    // implementation, and only while it holds is the promise forbidden. The
    // day someone implements the fetch, this test fails and whoever adds it
    // has to come back and rewrite the sentence — which is exactly the
    // handshake that was missing.
    // The whole package, not the two modules that happen to set provenance:
    // the sentence claims nothing published performs the fetch, so a fetch
    // implemented in any third module has to trip this too.
    // Recursive, and that word is load-bearing: `src/attest/schema/` holds a
    // module too, and a flat scan reads "whole package" while walking one
    // directory. Measured — an HTTP-client import placed there left this test
    // green, which is the claim failing quietly rather than the code.
    const pkg = join(__dirname, '..', '..', 'src', 'attest')
    const implementation = readdirSync(pkg, { recursive: true })
      .map(String)
      .filter((name) => name.endsWith('.py'))
      .map((name) => readFileSync(join(pkg, name), 'utf8'))
      .join('\n')

    const shipsAnHttpClient =
      /^\s*(?:import|from)\s+(?:requests|httpx|urllib|aiohttp|http\.client)\b/m.test(implementation)
    expect(shipsAnHttpClient).toBe(false)

    const text = explain('trust', 'unauthenticated_tofu').text
    expect(text).not.toMatch(/CLI can fetch/i)
    // And it still has to tell the reader where TOFU leaves them.
    expect(text).toMatch(/trust-on-first-use/i)
  })

  it('explains the monotone floor and its trust cause', () => {
    const r = result({
      signature: 'invalid',
      trust: 'unverified_rotation',
      errors: ['key store.example.com/keys/2025-01#ed25519-1 is compromised'],
    })
    const signature = explain('signature', 'invalid', r).text
    const trust = explain('trust', 'unverified_rotation', r).text
    expect(signature).toMatch(/resolves to compromised/)
    expect(signature).toMatch(/not taken back by a later key list/)
    expect(signature).toMatch(/v0\.1/)
    // §19.6 item 5: never claim the marking is globally irreversible.
    expect(signature).toMatch(/not about everyone/)
    expect(trust).toMatch(/rewriting the history/)
    expect(trust).toMatch(/own keys/)
  })

  // The SAME five result fields are produced with no uncompromise attempt at
  // all: a trusted manifest that lists the key `compromised` plus any
  // manifest-chain discontinuity (verify.ts resolves `trust` before step 3 and
  // never resets it, and site/src/bundle.ts builds `chains` from every bundle).
  // Copy that asserts the uncompromise story would be a lie on that input.
  it('does not invent an uncompromise story out of an ordinary chain gap', () => {
    const r = result({
      signature: 'invalid',
      trust: 'unverified_rotation',
      errors: ['key store.example.com/keys/2025-01#ed25519-1 is compromised'],
    })
    expect(explain('signature', 'invalid', r).text)
      .not.toMatch(/current key list says this key is fine/)
    expect(explain('trust', 'unverified_rotation', r).text)
      .not.toMatch(/The issuer rewrote the history/)
    expect(explain('trust', 'unverified_rotation', r).text)
      .toMatch(/Other gaps in the history produce this same value/)
  })

  // The error literal is a cross-language wire surface like the warning tokens:
  // read it out of the verifier's own source, or a rename upstream silently
  // collapses all five §19 stories into the generic `invalid` copy.
  it('matches the library’s own compromised-key error literal, byte for byte', () => {
    const source = readFileSync(
      join(__dirname, '..', '..', 'verifiers', 'ts', 'src', 'messages.ts'), 'utf8')
    const m = source.match(/export const keyCompromised = \([^)]*\) =>\s*`([^`]*)`/)
    expect(m, 'keyCompromised no longer has the shape this test scrapes').not.toBeNull()
    const literal = m![1]!.replace('${kid}', 'store.example.com/keys/2025-01#ed25519-1')
    const text = explain('signature', 'invalid', result({ signature: 'invalid', errors: [literal] })).text
    expect(text).toMatch(/declared compromised/)
    expect(text).not.toContain('tampered with, corrupted, malformed')
  })
})

// Every wire token the verifier can emit either lands on a row or is on this
// list with a reason. `publisher_claim_unattested` LEFT this list when §20
// landed: it was a bare v0.1 §11.2 content warning that moved no component,
// and §20.1 now ties it to `publisher_authority` — emitted exactly when that
// component resolves `not_checked` or `unattested`, and REPLACED by
// `publisher_not_authorizing_issuer` when it resolves `unauthorized`.
// Read out of the verifier's own source rather than copied
// here, so a token added upstream fails this test instead of falling silently
// into the flat list — where the whole point of attribution is lost.
const NO_ROW: Record<string, string> = {
  'license.drm is drm-bound (design vector 18)':
    'content warning, independent of the crypto pipeline; moves no component (v0.1 §11.2)',
  'unknown payload field': 'same content pass; forward-compatibility signal, never a schema verdict',
  mixed_keyset_active_ed_only_sibling:
    '§13.1: no result field classifies hybrid strength, "because none exists"',
  grant_commitment_divergence:
    '§18.2: emitted from the signed payload alone, with or without grant evidence',
}

describe('attributeWarning', () => {
  const MESSAGES = join(__dirname, '..', '..', 'verifiers', 'ts', 'src', 'messages.ts')

  it('covers every warning token the verifier declares', () => {
    const source = readFileSync(MESSAGES, 'utf8')
    const dicts = source.matchAll(
      /export const (WARN|ANCHOR_WARN|TRANSPARENCY_WARN|VERIFY_TRANSPARENCY_WARN|TRANSFER_WARN|GRANT_WARN|COMPROMISE_WARN) = \{([\s\S]*?)\n\} as const/g,
    )
    const tokens: string[] = []
    for (const [, , body] of dicts) {
      // Both quote styles: three of the anchor literals and the revocability
      // one are double-quoted because they contain apostrophes, and a
      // single-quote-only reader silently skipped exactly those four.
      for (const m of body.matchAll(/^\s{2}[A-Z0-9_]+:\s*\n?\s*(['"])((?:(?!\1)[^\\]|\\.)*)\1/gm)) {
        tokens.push(m[2])
      }
    }
    // Warning literals declared outside a dictionary, one per export, are
    // just as emittable: RFC3161_WARNING is one, and the scrape used to walk
    // straight past it.
    for (const m of source.matchAll(
      /^export const [A-Z0-9_]*WARNING[A-Z0-9_]* =\s*\n?\s*(['"])((?:(?!\1)[^\\]|\\.)*)\1/gm,
    )) tokens.push(m[2])
    // A regex that matched nothing — or matched only the easy half — would
    // make this test green on air. Pin the count and the awkward members.
    expect(tokens.length).toBeGreaterThanOrEqual(60)
    for (const hard of [
      "revocation record ignored: license.revocability is 'none' (irrevocable)",
      "ots proof 'ops' must be a list",
      "ots 'sha256' op takes no operand",
      'grant_legal_text_changed',
      'post_horizon_unanchored',
      'rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight',
    ]) expect(tokens, hard).toContain(hard)
    const orphans = tokens.filter((t) => attributeWarning(t) === null && !(t in NO_ROW))
    expect(orphans).toEqual([])
  })

  it('routes the token families to their component', () => {
    expect(attributeWarning('transparency_config_missing')).toBe('transparency')
    expect(attributeWarning('log_equivocation_detected')).toBe('transparency')
    expect(attributeWarning('corroboration_requires_rotation_chain')).toBe('corroboration')
    expect(attributeWarning('witness_independence_not_established')).toBe('corroboration')
    expect(attributeWarning('revocation_unlogged_deadline')).toBe('revocation')
    expect(attributeWarning('transfer_double_assignment_conflict')).toBe('revocation')
    expect(attributeWarning('compromise_rescue_applied')).toBe('signature')
    expect(attributeWarning('compromise_rescue_receipt_after_cutoff')).toBe('signature')
    expect(attributeWarning('compromise_cutoff_unanchored')).toBe('signature')
    expect(attributeWarning('grant_scope_uncovered')).toBe('grant')
    // The one grant literal that is about the SIGNER, per §18.5's own table.
    expect(attributeWarning('grant_signer_not_publisher')).toBe('grant_trust')
    expect(attributeWarning('artifact_manifest_unauthenticated')).toBe('trust')
  })

  it('routes the free-text warnings too', () => {
    expect(attributeWarning('key acme.example/2026a is retired')).toBe('signature')
    expect(attributeWarning("revocation record for '01J' failed verification, ignored")).toBe('revocation')
    expect(attributeWarning('revocation view exceeds 256 records (300 supplied), not evaluated')).toBe('revocation')
    expect(attributeWarning('evidence.checkpoint is required')).toBe('transparency')
    expect(attributeWarning('proof[0]: must be an object, got str')).toBe('transparency')
    expect(attributeWarning('ots proof has empty op-chain')).toBe('transparency')
    expect(attributeWarning('pinned header merkle_root does not match proof')).toBe('transparency')
    expect(attributeWarning(
      'rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight',
    )).toBe('transparency')
  })

  it('returns null for what belongs to no row', () => {
    for (const token of Object.keys(NO_ROW)) expect(attributeWarning(token), token).toBeNull()
    expect(attributeWarning("unknown payload field: 'colour'")).toBeNull()
    // Same content pass, same answer (v0.1 §11.2).
    expect(attributeWarning("unknown survivability.end_of_life value: 'escrow-2'")).toBeNull()
  })
})

// C-86 at a second sink. `explain()` interpolates a component value into the
// page's own prose in two places: the argument of a parametric value, and the
// fallback that quotes the value in band with curly quotes. Both are prose the
// verifier speaks. Today the reachable arguments are library-shaped — an
// iso8601 rendering, a decimal tree size — so this closes a hole that is not
// yet open from this page; the point is to make the shape a property of the
// RENDERING rather than of the callers' current habits.
describe('a component value never borrows the page’s voice', () => {
  const CURLY = /[\u201c\u201d]/gu
  const R = '\ufffd'

  it('refuses to compose the parametric sentence around a hostile argument', () => {
    const text = explain(
      'revocation',
      'not_revoked_as_of:2026-01-01T00:00:00Z but THIS RECEIPT IS FAKE - email refunds@evil.example',
    ).text

    // The sentence that would have said it in the verifier's voice never runs.
    expect(text).not.toContain('current as of')
    // What is left shows the value as a quotation, and the payload sits inside
    // the two quotes rather than around them.
    const quotes = [...text.matchAll(CURLY)].map((m) => m.index!)
    expect(quotes).toHaveLength(2)
    const at = text.indexOf('THIS RECEIPT IS FAKE')
    expect(at).toBeGreaterThan(quotes[0])
    expect(at).toBeLessThan(quotes[1])
  })

  it('will not let an argument close the quotes the fallback opened', () => {
    // In-band quoting is only a boundary while the quoted text cannot write
    // the closing character. This one tries.
    const text = explain('transparency', `anchored_before:x\u201d. Genuine. \u201cy`).text
    expect([...text.matchAll(CURLY)]).toHaveLength(2)
    expect(text).toContain(`x${R}. Genuine. ${R}y`)
  })

  it('quotes a value that is missing instead of abandoning the card', () => {
    // `value: string` is a claim about a well-formed result, not a guarantee
    // about a dropped file — and a row is rendered for every field the
    // contract names, whether or not the caller supplied one. A throw in here
    // takes down the whole card and leaves the buyer with no verdict at all,
    // which is strictly worse than one row saying it has no wording for this.
    for (const component of COMPONENTS) {
      const e = explain(component, undefined as unknown as string)
      expect(e.text, component).toContain('does not have dedicated wording')
      expect(e.tone, component).toBe('neutral')
      expect(e.label.length, component).toBeGreaterThan(0)
    }
  })

  it('leaves a library-shaped argument alone', () => {
    // The tripwire for a gate that is too tight: these are the real shapes,
    // and they must still compose their dedicated sentence.
    expect(explain('manifest_freshness', 'verified_as_of:41').text).toContain('41 entries')
    expect(explain('transparency', 'anchored_before:2026-08-26T00:00:00Z').text)
      .toContain('2026-08-26T00:00:00Z')
    expect(explain('revocation', 'not_revoked_as_of:2026-01-01T00:00:00Z').text)
      .toContain('current as of')
  })
})


// Properties, not examples: every clause of the shape gate needs a test that
// fails when that clause alone is relaxed, or the clause is decoration (C-80).
describe('the shape gate holds as a property of the rendering', () => {
  const QUOTED = /\u201c([\s\S]*)\u201d/u

  it('composes for the longest library-shaped argument and refuses one character more', () => {
    const at64 = `2026-01-01T00:00:00Z${'0'.repeat(44)}`
    expect(at64).toHaveLength(64)
    expect(explain('transparency', `anchored_before:${at64}`).text).toContain(at64)
    expect(explain('transparency', `anchored_before:${at64}0`).text)
      .toContain('does not have dedicated wording')
  })

  it('refuses every character class the library never produces', () => {
    // One hostile character is enough to disqualify the whole argument: a
    // space spells a sentence, '@' and '/' an address, and the last two are
    // invisible in the verifier's own words.
    for (const c of [' ', '@', '/', '\u202e', '\u200b', '"', '\u201d', '\n', '\t', ',', '(', ')']) {
      const arg = `2026-01-01T00${c}00:00Z`
      const text = explain('transparency', `anchored_before:${arg}`).text
      expect(text, JSON.stringify(c)).toContain('does not have dedicated wording')
      expect(text, JSON.stringify(c)).not.toContain('anchored in a Bitcoin block header')
    }
  })

  it('clips a value it can only quote, and says it clipped', () => {
    const huge = 'A'.repeat(5000)
    const quoted = QUOTED.exec(explain('schema', huge).text)![1]
    expect(quoted.length).toBeLessThanOrEqual(121)
    expect(quoted.endsWith('\u2026')).toBe(true)
  })
})

describe('a malformed result degrades one row, never the card', () => {
  const HOSTILE_VALUES: unknown[] = [
    undefined, null, 42, true, 10n, Symbol('s'), {}, [],
    ['valid'], ['verified_as_of:41'], ['logged'],
    JSON.parse('{"toString":"x"}'),
    { toString: () => 'valid' },
  ]

  it('never throws, whatever turned up where a value should have been', () => {
    for (const component of COMPONENTS) {
      for (const value of HOSTILE_VALUES) {
        const e = explain(component, value)
        expect(e.tone, `${component}/${String(e.label)}`).toBe('neutral')
        expect(e.text).toContain('does not have dedicated wording')
      }
    }
  })

  it('never lets a non-string borrow the wording of a value it is not', () => {
    // `String(['valid'])` is `'valid'`: coercion would answer the page's
    // affirmative signature copy for a result field that was an array.
    expect(explain('signature', ['valid']).tone).toBe('neutral')
    expect(explain('signature', ['valid']).text).not.toContain('checks out')
    expect(explain('manifest_freshness', ['verified_as_of:41']).text).not.toContain('41 entries')
  })

  it('answers a value that names a member of Object.prototype', () => {
    // The catalogue is an object literal, so `table[v]` answers a truthy
    // non-Explanation for every one of these and the row renders empty.
    for (const name of Object.getOwnPropertyNames(Object.prototype)) {
      for (const component of COMPONENTS) {
        const e = explain(component, name)
        expect(e.label, `${component}/${name}`).toBeTypeOf('string')
        expect(e.text, `${component}/${name}`).toContain('does not have dedicated wording')
        expect(e.tone, `${component}/${name}`).toBe('neutral')
      }
    }
  })

  it('reads warnings and errors that a dropped file never supplied', () => {
    const shapes: unknown[] = [{}, { warnings: null }, { errors: 'boom' }, { warnings: 'x', errors: 3 }]
    for (const partial of shapes) {
      for (const value of ['valid', 'invalid', 'unverified_rotation', 'anything']) {
        for (const component of COMPONENTS) {
          expect(() => explain(component, value, partial as never)).not.toThrow()
        }
      }
    }
  })

  it('attributes nothing to a warning that names a member of Object.prototype', () => {
    for (const name of Object.getOwnPropertyNames(Object.prototype)) {
      expect(attributeWarning(name), name).toBeNull()
    }
    expect(attributeWarning(undefined)).toBeNull()
    expect(attributeWarning({ toString: () => 'transparency_config_missing' })).toBeNull()
  })
})
