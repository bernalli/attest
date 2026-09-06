import { loadsStrict } from 'attest-verifier'
import { explainVerdict } from '../../site/src/explain.js'
import type { SurfaceFacts } from '../../site/src/explain.js'
import { renderResult } from '../../site/src/render.js'
import type { VerifyJob } from '../../site/src/intake.js'
import type { VerifyRun } from '../../site/src/run.js'
import { desktopVerdict, HEADLINES, offlineLimitText } from './verdict.js'

/**
 * The result card, composed from the site's renderer with one sanctioned difference:
 * the headline, and where the title comes from.
 *
 * Everything below the headline — the rows, their ratified copy, warning attribution,
 * the raw JSON — is the site's own `renderResult` output, imported rather than copied,
 * so the two surfaces cannot drift into saying different things about the same result.
 */

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

// The two shapes the schema gate already guarantees for the fields quoted below
// (spec §11 step 5). Restated here on purpose: the title must be readable as a
// bounded string, not as "whatever the payload happens to hold", and if the
// schema ever loosens these two fields the title stays bounded anyway.
//
// The receipt-id shape is DUPLICATED, not imported: each core now has exactly one
// owner — `verifiers/ts/src/ids.ts` for the verifier package and `src/attest/ulid.py`
// for the Python core — but the package exports neither, so this application keeps
// its own copy.
//
// Deliberately no count here, and no standing rule asking an editor to remember the
// other copies: a number written into a comment is stale the moment a copy is added
// or removed, and a rule nobody executes is not a rule.
// `tests/test_shared_predicate_ownership.py` pins every location and its count in
// both languages and fails on a new one. Read it there, not here.
//
// What does belong here: on a surface a buyer reads, this shape check is the primary
// defence rather than a convenience.
const RECEIPT_ID_SHAPE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/
const ISSUER_ID_SHAPE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/

/**
 * The title, derived from the bytes the signature covers.
 *
 * The name a file arrives under is chosen by whoever handed the file over and is
 * covered by no signature, so the title comes out of the payload instead.
 *
 * The PRIMARY defence is the shape check on each value, not a gate on some other
 * component of the verdict. `site/src/bundle.ts` already works this way — it accepts a
 * receipt id only when `RECEIPT_ID_RE` matches it — and the reason is that a shape
 * check holds on its own, while a gate borrows a guarantee someone else maintains. The
 * two regexes above are that check, and they are byte-identical to the ones the bundle
 * parser and the schema validator already carry.
 *
 * What made the gate necessary to add as well: a valid signature alone says the bytes
 * were signed by SOME key the file itself named — under trust-on-first-use the attacker
 * supplies the key and the manifest too — so it says nothing about their shape. Measured
 * against the earlier version, which gated on the signature only, a schema-invalid
 * payload put 200,000 characters, a right-to-left override, a Cyrillic homoglyph domain,
 * and the string "01M0YX8RAPJ5BQ8WJSS4CBK43F — store.nebula.example ✅ VERIFIED PURCHASE"
 * straight into this heading, above the verdict. The shape checks alone would refuse all
 * of those; the schema gate adds the remaining case, where both quoted fields are
 * well-formed while the rest of the payload is not.
 */
export function cardTitle(envelopeBytes: Uint8Array, run: VerifyRun): string {
  if (run.result.signature !== 'valid' || run.result.schema !== 'valid')
    return 'Receipt that does not verify'
  try {
    const envelope = loadsStrict(envelopeBytes)
    if (!isObject(envelope)) return 'Receipt'
    const payload = envelope['payload']
    if (!isObject(payload)) return 'Receipt'

    const rawId = payload['receipt_id']
    const receiptId = typeof rawId === 'string' && RECEIPT_ID_SHAPE.test(rawId) ? rawId : null
    const issuer = isObject(payload['issuer']) ? payload['issuer'] : null
    const rawIssuerId = issuer ? issuer['id'] : undefined
    const issuerId =
      typeof rawIssuerId === 'string' && ISSUER_ID_SHAPE.test(rawIssuerId) ? rawIssuerId : null

    if (receiptId && issuerId) return `${receiptId} — ${issuerId}`
    if (receiptId) return receiptId
    return 'Receipt'
  } catch {
    // A payload that will not parse is not a title. The rows below still report why.
    return 'Receipt'
  }
}

function headlineFor(
  run: VerifyRun,
  facts: SurfaceFacts | undefined,
): { label: string; text: string; className: string } {
  const verdict = desktopVerdict(run.ok, run.result.trust)
  if (verdict === 'failed') {
    // Reused verbatim: one red wording in the project, never two that can drift.
    const red = explainVerdict(false)
    return { label: red.label, text: red.text, className: 'verdict tone-bad' }
  }
  const headline = HEADLINES[verdict]
  // The amber headline names what this check could not settle, and one of the
  // three is revocation — so it has to know whether a feed was consulted.
  // `revocation` reads `unknown` for "no file" and for "an empty feed" alike
  // (§14.3), which is exactly why this cannot be read off the result.
  const text =
    verdict === 'offline_limit'
      ? offlineLimitText(
          typeof run.result.revocation === 'string' ? run.result.revocation : '',
          facts?.revocationFeedConsulted === true,
        )
      : headline.text
  // Four states, four appearances. `key_history_gap` keeps `tone-warn` — it IS
  // cautionary — and adds a class of its own, because sharing one class with
  // `offline_limit` would leave the two distinguishable only by their wording, and a
  // reader who has learned that amber means the ordinary offline limit would read an
  // anomaly as the limit.
  const extra = verdict === 'key_history_gap' ? ' verdict-key-gap' : ''
  return { label: headline.label, text, className: `verdict tone-${headline.tone}${extra}` }
}

/**
 * Takes the whole job rather than loose arguments: the safety of the title rests on
 * `run` describing exactly THESE bytes, and three independent parameters let a caller
 * pair the bytes of one receipt with the verdict of another — silently, in a
 * multi-receipt bundle. Deriving both from the job makes that pairing impossible.
 *
 * `droppedFileName` is the ONE string on this card the signature does not cover, and it
 * arrives as its own parameter because nothing inside the job carries it any more:
 * `job.label` is the receipt id read out of the signed payload. Printing that under
 * "File you dropped … (this name is not signed)" would state the exact opposite of the
 * truth, in a file that is downloaded once and can never be corrected.
 */
export function renderDesktopCard(
  job: VerifyJob,
  run: VerifyRun,
  droppedFileName: string,
  facts?: SurfaceFacts,
): HTMLElement {
  const card = renderResult(cardTitle(job.envelopeBytes, run), run, facts)

  // Fail CLOSED on the seam. The node being replaced carries the site's binary
  // headline, which on an `ok` receipt reads "Receipt verifies" — the single most
  // reassuring sentence in the project, reachable by a receipt signed with a key
  // nobody has vouched for. If the seam is ever gone, returning the card as-is would
  // ship that sentence. Throwing is honest; the app shell renders the site's own
  // renderVerifyFailure card instead.
  const badges = card.querySelectorAll('.verdict')
  if (badges.length !== 1)
    throw new Error(`desktop card: expected one .verdict node to replace, found ${badges.length}`)

  const headline = headlineFor(run, facts)
  const replacement = document.createElement('p')
  replacement.className = headline.className
  const strong = document.createElement('strong')
  strong.textContent = headline.label
  const span = document.createElement('span')
  span.textContent = ` ${headline.text}`
  replacement.append(strong, span)
  badges[0]!.replaceWith(replacement)

  // The name the file arrived under is still worth showing — it is how a person finds
  // the file again — but it is shown as data, below the title, labelled for what it is.
  // `textContent` throughout: a name is text, never markup. Fail closed here too, since
  // the qualifier "this name is not signed" is the whole reason the string is allowed
  // on the card at all.
  const header = card.querySelector('header')
  if (!header) throw new Error('desktop card: the site render has no header to attribute the name in')
  const provenance = document.createElement('p')
  provenance.className = 'supplied-name'
  provenance.textContent = `File you dropped: ${droppedFileName} (this name is not signed)`
  header.appendChild(provenance)

  return card
}
