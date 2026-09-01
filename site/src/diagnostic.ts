// Segmentation of a library-composed diagnostic into page-owned framing and
// untrusted operands (C-86). Default-deny: anything not positively recognized
// is ALL operand. The tables below are page-owned copies of wire strings from
// verifiers/ts/src/messages.ts, which freezes them ("DO NOT paraphrase") —
// they are matched exactly and re-emitted from HERE, never sliced from input.
//
// Why copies rather than imports: `attest-verifier` exports only its root, and
// the composers are not re-exported. A missing or stale template costs
// readability — the diagnostic degrades to `opaque`, entirely quoted — and
// never safety. That asymmetry is the whole design.

export type DiagnosticPart =
  | { kind: 'literal'; text: string } // page-owned template text
  | { kind: 'operand'; text: string } // untrusted; neutralized at render time

export type SegmentedDiagnostic =
  | { kind: 'token'; code: string } // whole string is a wire token
  | { kind: 'known-literal'; text: string } // whole string is a known fixed literal
  | { kind: 'composed'; parts: DiagnosticPart[] } // template match
  | { kind: 'opaque'; operand: string } // nothing matched: all operand

// A wire token cannot spell a sentence, an email address or a URL: no spaces,
// no dots, no '@'. Every key of explain.ts's EXACT table matches this shape.
const TOKEN_RE = /^[a-z0-9_]+$/

const OPERAND: unique symbol = Symbol('operand')
type Template = readonly (string | typeof OPERAND)[]

const KNOWN_LITERALS = new Set<string>([
  // messages.ts ERR — fixed strings, no operand
  'envelope is not a JSON object',
  "envelope missing object member 'payload'",
  "envelope missing array member 'signatures'",
  'malformed signature block',
  "malformed signature block: 'kid'/'sig' must be strings",
  'malformed payload: missing issuer.id',
  'issuer_mismatch: kid domain does not match payload issuer.id',
  'signature verification failed',
  'floats are not allowed in the attest-JCS profile',
  'lone surrogate not allowed in the attest-JCS profile',
  'type not representable in JSON',
  'maximum nesting depth exceeded',
  'hybrid envelope requires exactly two signatures',
  'hybrid envelope requires algs Ed25519 and ML-DSA-65 in order',
  'hybrid envelope signatures must share a single kid',
  "malformed signature block: 'kid' must be a string",
  "malformed signature block: 'sig' must be a string",
  'ML-DSA-65 signature verification failed',
  // messages.ts WARN + RFC3161_WARNING — fixed prose warnings
  'license.drm is drm-bound (design vector 18)',
  "revocation record ignored: license.revocability is 'none' (irrevocable)",
  'rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight',
])

const TEMPLATES: readonly Template[] = [
  ['unknown payload field: ', OPERAND],
  ['no trusted manifest for issuer ', OPERAND],
  ['key ', OPERAND, ' is retired'],
  ['key ', OPERAND, ' is compromised'],
  ['no key ', OPERAND, ' in issuer manifest'],
  ['issuer manifest for ', OPERAND, ' is not self-consistent: its own signature does not verify'],
  ['revocation record for ', OPERAND, ' failed verification, ignored'],
  ['revocation record for ', OPERAND, ' outside refund window, ignored'],
  ['unknown survivability.end_of_life value: ', OPERAND],
  ['issued_at ', OPERAND, ' outside key validity window'],
  ['key entry for kid ', OPERAND, ' has no ML-DSA-65 public key'],
  ['duplicate object key: ', OPERAND],
  ['non-string object key: ', OPERAND],
  ['unsupported attest_version: ', OPERAND],
  ['unsupported signature algorithm: ', OPERAND],
  ['signatures must contain exactly one entry, got ', OPERAND],
  ['malformed key material: ', OPERAND],
  ['malformed signature material: ', OPERAND],
  ['input is not valid UTF-8: ', OPERAND],
  ['invalid JSON: ', OPERAND],
  ['issuer manifest lists duplicate kid(s): ', OPERAND],
  ['envelope exceeds ', OPERAND, ' bytes'],
  ['issuer manifest exceeds ', OPERAND, ' keys'],
  ['revocation view exceeds ', OPERAND, ' records (', OPERAND, ' supplied), not evaluated'],
  [
    'revocation view exceeds ',
    OPERAND,
    ' records (',
    OPERAND,
    ' supplied), cannot certify a revocable receipt',
  ],
  ['integer out of I-JSON safe range: ', OPERAND],
]

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const compiled = TEMPLATES.map((parts) => ({
  parts,
  re: new RegExp(
    '^' + parts.map((p) => (p === OPERAND ? '([\\s\\S]+)' : escapeRegExp(p))).join('') + '$',
  ),
}))

/** Split a diagnostic into what the page may say in its own voice and what it
 * may only quote.
 *
 * Takes `unknown`, not `string`, and that is deliberate. The library types
 * `warnings[]`/`errors[]` as `string[]`, but the page is handed whatever the
 * dropped file produced, through JSON. A TypeError raised in here would
 * abandon the whole render and leave the buyer with no verdict at all — a
 * strictly worse outcome than one warning shown as an unrecognized quotation.
 * A non-string is quarantined without being coerced: coercing first would let
 * an object whose `toString` spells a known template borrow the page's voice.
 */
export function segmentDiagnostic(diagnostic: unknown): SegmentedDiagnostic {
  if (typeof diagnostic !== 'string') {
    return { kind: 'opaque', operand: describeNonString(diagnostic) }
  }
  if (TOKEN_RE.test(diagnostic)) return { kind: 'token', code: diagnostic }
  if (KNOWN_LITERALS.has(diagnostic)) return { kind: 'known-literal', text: diagnostic }
  for (const { parts, re } of compiled) {
    const m = re.exec(diagnostic)
    if (m === null) continue
    let capture = 1
    const out: DiagnosticPart[] = parts.map((p) =>
      p === OPERAND
        ? { kind: 'operand' as const, text: m[capture++] }
        : { kind: 'literal' as const, text: p },
    )
    return { kind: 'composed', parts: out }
  }
  return { kind: 'opaque', operand: diagnostic }
}

/** Name the shape of a value that should have been a diagnostic, without
 * quoting anything it might contain. Says what arrived, not what it said. */
function describeNonString(value: unknown): string {
  if (value === null) return '(null instead of a diagnostic)'
  if (Array.isArray(value)) return '(an array instead of a diagnostic)'
  return `(a ${typeof value} instead of a diagnostic)`
}
