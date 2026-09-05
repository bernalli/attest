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
    text:
      'These exact terms were signed by the key this file names, and nothing in them has ' +
      'changed since. Three things this app cannot settle, offline, on purpose: whether ' +
      'that key really belongs to the seller it names; whether the seller has since revoked ' +
      'this receipt, since no revocation feed was consulted; ' +
      'and whether anyone supplied this receipt’s binding secret. Possession of that secret ' +
      'does not establish who made the purchase. The rows below say which checks ran.',
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
