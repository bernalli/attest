import type { VerificationResult } from 'attest-verifier'

type Trust = VerificationResult['trust']

/**
 * The headline verdict this app is allowed to show.
 *
 * Four states, not two. The shared web verifier's headline is a boolean over the
 * four-gate `ok` of the spec — signature, schema, revocation, errors — which does not
 * include key trust. On a page a reader explores at leisure that is a label with the
 * detail underneath; in an app that answers "double click, verdict out", the headline
 * IS the verdict, and everything under it is optional reading.
 *
 * So `ok` alone cannot decide it. A receipt can pass all four gates while being signed
 * by a key nobody has ever vouched for — which, today, is every receipt any attest tool
 * can produce, since no shipped tool reaches the out-of-band `verified` level.
 */
export type DesktopVerdict = 'verified' | 'offline_limit' | 'key_history_gap' | 'failed'

export interface Headline {
  label: string
  text: string
  tone: 'good' | 'warn' | 'bad'
}

const OFFLINE_LIMIT_HEAD =
  'These exact terms were signed by the key this file names, and nothing in them has ' +
  'changed since. Three things this app cannot settle, offline, on purpose: whether ' +
  'that key really belongs to the seller it names; '

const OFFLINE_LIMIT_TAIL =
  '; and whether anyone supplied this receipt’s binding secret. Possession of that secret ' +
  'does not establish who made the purchase. The rows below say which checks ran.'

const NOT_REVOKED_AS_OF = 'not_revoked_as_of:'

// The same guard `explain.ts` puts on a parametric argument, for the same
// reason: the timestamp is interpolated into a sentence spoken in the
// verifier's own voice, so it is composed only when it has the shape the
// library produces. Anything else falls back to a clause that quotes nothing.
const TIMESTAMP_RE = /^[0-9A-Za-z:+.\-]{1,64}$/

/**
 * The revocation clause of the amber headline.
 *
 * It has to vary, and that is a requirement rather than a nicety. v0.1 §14.3
 * fixes the distinction the RESULT cannot carry: a rail with no file was not
 * consulted, a rail holding an empty array was consulted and found nothing,
 * `revocation` reads `unknown` for both. The old fixed wording — "since no
 * revocation feed was consulted" — is therefore false on every screen where a
 * feed IS loaded, and it sits above a rail line saying so in the same view.
 *
 * `feedConsulted` is the page's own state, never read off the result.
 */
export function offlineLimitText(revocation: string, feedConsulted: boolean): string {
  return `${OFFLINE_LIMIT_HEAD}${revocationClause(revocation, feedConsulted)}${OFFLINE_LIMIT_TAIL}`
}

function revocationClause(revocation: string, feedConsulted: boolean): string {
  if (revocation.startsWith(NOT_REVOKED_AS_OF)) {
    const asOf = revocation.slice(NOT_REVOKED_AS_OF.length)
    // `feedConsulted` gates this branch too. The value can only come from an
    // authenticated record inside a view the page supplied, so today the two
    // always agree — but "the revocation feed you supplied" is a claim about
    // the page's own state, and a sentence that reads it off the RESULT instead
    // is one refactor away from saying it when no feed was ever consulted.
    if (feedConsulted && TIMESTAMP_RE.test(asOf))
      return (
        'whether the seller has since revoked this receipt — the revocation feed you ' +
        `supplied lists nothing for it as of ${asOf}, which is as current as that feed goes`
      )
    return 'whether the seller has since revoked this receipt — the Revocation row below says what this check settled and what it did not'
  }
  if (revocation === 'unknown' && feedConsulted)
    return (
      'whether the seller has since revoked this receipt — the revocation feed you ' +
      'supplied lists nothing for it, and carries no signed timestamp saying how current ' +
      'it is'
    )
  if (revocation === 'unknown') return 'whether the seller has since revoked this receipt, since no revocation feed was consulted'
  // `revoked` and `transferred` cap `ok`, so they never reach an amber headline;
  // `invalid_revocation_ignored` does. Naming no cause is the point — the row
  // below states which of the three it was, and this sentence must not guess.
  return 'whether the seller has since revoked this receipt — the Revocation row below says what this check settled and what it did not'
}

/**
 * The headline copy. Draft pending the project's copy ratification gate.
 *
 * `failed` is absent on purpose: the red headline is reused verbatim from the shared
 * catalogue rather than restated here, so there is exactly one red wording in the
 * project and no chance of the two drifting apart.
 *
 * None of these texts point the reader at a remedy: no shipped tool reaches the
 * out-of-band `verified` tier today, and an artifact that is downloaded once and never
 * updated must not freeze an instruction that does not work.
 */
export const HEADLINES: Record<Exclude<DesktopVerdict, 'failed'>, Headline> = {
  offline_limit: {
    label: 'Checks out — as far as an offline check can go',
    tone: 'warn',
    // Composed, not written twice: this is the no-feed reading of the very
    // sentence `offlineLimitText` builds, so the catalogue entry and the live
    // headline cannot drift into saying different things.
    text: offlineLimitText('unknown', false),
  },
  key_history_gap: {
    label: 'Signed — but this seller’s key history does not add up',
    tone: 'warn',
    text:
      'The signature over these exact terms checks out. What did not is the seller’s own ' +
      'record of its keys: a newer key list is not signed by a key from the previous one, ' +
      'so this app cannot follow the history from one to the next. That is not proof of ' +
      'anything wrong, and it is not the ordinary offline limit either — it is a gap where ' +
      'there should not be one. The Key trust row below says it in the spec’s own words.',
  },
  verified: {
    label: 'Receipt verifies',
    tone: 'good',
    text:
      'Signature valid, schema valid, not revoked as far as this check could see, no errors ' +
      '— and the issuer’s keys were verified out of band, not taken from the file itself.',
  },
}

export function desktopVerdict(ok: boolean, trust: Trust): DesktopVerdict {
  if (!ok) return 'failed'
  switch (trust) {
    case 'verified':
      return 'verified'
    case 'unauthenticated_tofu':
      return 'offline_limit'
    // NOT the same state as the one above: the keys did not merely go unvouched, the
    // issuer's own key history has a gap the verifier could not close. Collapsing it
    // into `offline_limit` would put a headline describing an ABSENCE over a result
    // reporting an ANOMALY.
    case 'unverified_rotation':
      return 'key_history_gap'
    default: {
      // The `never` assignment keeps the compile-time exhaustiveness a bare switch
      // already had; the throw adds the half it did not have. `tsc` reads `Trust` out
      // of attest-verifier's BUILT declarations, so a fourth trust value added to the
      // verifier's source but not yet rebuilt compiles here and arrives at runtime —
      // measured: the bare switch then returned `undefined` and the card died later on
      // `headline.tone`, in a message naming neither this file nor the value.
      const unknown: never = trust
      throw new Error(`desktopVerdict: unknown trust value ${JSON.stringify(unknown)}`)
    }
  }
}
