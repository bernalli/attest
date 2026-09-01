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
    // No default branch, deliberately: if the verifier ever grows a fourth trust value,
    // this switch stops compiling instead of quietly returning undefined where a
    // headline should be.
  }
}
