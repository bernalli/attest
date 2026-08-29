import type { VerificationResult } from 'attest-verifier'

export type Tone = 'good' | 'warn' | 'bad' | 'neutral'
export interface Explanation {
  label: string
  text: string
  tone: Tone
}
export type Component =
  | 'signature' | 'schema' | 'binding' | 'trust'
  | 'publisher_authority' | 'publisher_authority_trust'
  | 'revocation' | 'grant' | 'grant_trust'
  | 'transparency' | 'corroboration' | 'manifest_freshness'

// Compile-time proof that this file covers the WHOLE result contract: every
// string-valued field of `VerificationResult` must be a `Component` with copy
// below. When a future stage adds a component, `tsc` fails here rather than
// letting the new field reappear where the five Stage-2/4 ones spent a year —
// visible only inside the collapsed raw JSON.
type ResultComponentKeys = {
  [K in keyof VerificationResult]: VerificationResult[K] extends string ? K : never
}[keyof VerificationResult]
type Unexplained = Exclude<ResultComponentKeys, Component>
const _EVERY_RESULT_FIELD_IS_EXPLAINED: Unexplained extends never ? true : never = true
void _EVERY_RESULT_FIELD_IS_EXPLAINED

export interface ComponentGroup {
  question: string
  note: string
  components: Component[]
}

// Ten rows read as a wall; three questions read as an answer. The grouping is
// the one hierarchy the spec itself supports: what is true OF the receipt,
// what is true NOW, and what is true FOR OTHERS. `grant` sits under "does it
// still hold" because that is where a person looks for it, not under a fourth
// question about pledges that nobody asks in those words.
export const GROUPS: ComponentGroup[] = [
  {
    question: 'Is it authentic?',
    note: 'What the file proves on its own, offline, with no network and no help from us: who signed these exact terms, and whose receipt it is. The last two rows ask a further question a buyer of an unfamiliar store actually asks — was this seller entitled to sell it — and they are the only rows here that need a document beyond the receipt: the publisher’s own signed authorization, which this page is not handed.',
    components: ['signature', 'schema', 'binding', 'trust', 'publisher_authority', 'publisher_authority_trust'],
  },
  {
    question: 'Does it still hold?',
    note: 'What may have happened since it was signed — a refund, a transfer, a promise coming due. This page consults no live feed; it reports only what the file and its own evidence can settle.',
    components: ['revocation', 'grant', 'grant_trust'],
  },
  {
    question: 'Has anyone else seen it?',
    note: 'Whether this receipt was published in a public, append-only log. This is corroboration, never authenticity, with one narrow exception named on the Signature row: an ANCHORED time on the Transparency row — not mere publication, which is never enough — can spare a receipt whose signing key its issuer later declared compromised (spec §19). Outside that case, nothing here is needed to make a valid receipt valid, and being logged has never made an invalid one valid (spec §10).',
    components: ['transparency', 'corroboration', 'manifest_freshness'],
  },
]

export const COMPONENTS: Component[] = GROUPS.flatMap((g) => g.components)

// One entry per (component, value). Register: honest, concrete, no hype —
// same voice as README.md and docs/faq.md. Spec section pointers included
// so a curious reader can go straight to the normative text.
const CATALOG: Record<Component, Record<string, Explanation>> = {
  signature: {
    valid: {
      label: 'Signature',
      tone: 'good',
      text: 'The issuer’s Ed25519 signature over the canonical payload checks out: these exact terms were signed by the key identified in the issuer’s manifest, and nothing in them has changed since (spec §10, §11 step 4).',
    },
    invalid: {
      label: 'Signature',
      tone: 'bad',
      text: 'This receipt does not carry a valid signature from the issuer’s published key material — it may be tampered with, corrupted, malformed, or signed by a key this verifier has no manifest for. The errors below say exactly which check failed.',
    },
  },
  schema: {
    valid: {
      label: 'Schema',
      tone: 'good',
      text: 'The signed payload matches the attest v0.1 receipt schema: every required field is present with the right shape, so other tools will read this receipt the same way this one does (spec §11 step 5).',
    },
    invalid: {
      label: 'Schema',
      tone: 'bad',
      text: 'The signature may check out, but the payload does not match the attest v0.1 receipt schema — a conforming issuer should never have produced it. Treat it with suspicion.',
    },
    not_checked: {
      label: 'Schema',
      tone: 'neutral',
      text: 'Schema validation never ran, because verification stopped at an earlier step — there is no valid signature to make the payload worth validating (spec §11: short-circuit order).',
    },
  },
  binding: {
    proven: {
      label: 'Buyer binding',
      tone: 'good',
      text: 'The disclosed identifier and salt reproduce the buyer commitment sealed inside the signed payload — whoever supplied them is the buyer this receipt was issued to (spec §8.1).',
    },
    not_proven: {
      label: 'Buyer binding',
      tone: 'warn',
      text: 'A binding proof was attempted but did not reproduce the sealed buyer commitment — wrong identifier, wrong salt, or a receipt that simply is not theirs (spec §8).',
    },
    not_checked: {
      label: 'Buyer binding',
      tone: 'neutral',
      text: 'Nobody attempted to prove who this receipt belongs to — the receipt is genuine either way; binding only says whose it is. Use the panel above with the receipt’s salt to prove it (spec §8).',
    },
  },
  trust: {
    verified: {
      label: 'Key trust',
      tone: 'good',
      text: 'The issuer’s key manifest was fetched over TLS from the issuer’s own domain — the strongest provenance attest v0.1 defines (spec §7.4).',
    },
    unauthenticated_tofu: {
      label: 'Key trust',
      tone: 'warn',
      text: 'The issuer’s keys came from inside the file you dropped, not from the issuer’s website — the math checks out, but a browser cannot confirm who published these keys (and this page never phones home to try). That is trust-on-first-use, reported honestly; the attest CLI can fetch the manifest over TLS for the “verified” level (spec §7.4).',
    },
    unverified_rotation: {
      label: 'Key trust',
      tone: 'warn',
      text: 'The issuer’s key manifest history has a gap: a newer manifest is not signed by a key from the previous trusted one, so continuity cannot be proven (spec §7.3). The signature math still ran, but key provenance deserves suspicion.',
    },
  },
  revocation: {
    unknown: {
      label: 'Revocation',
      tone: 'neutral',
      text: 'No revocation feed was consulted, so this verifier honestly reports “unknown” instead of guessing — like a paper receipt, the absence of a revocation check does not erase the signature (spec §11.2). The CLI can check a feed when one is available.',
    },
    revoked: {
      label: 'Revocation',
      tone: 'bad',
      text: 'The issuer has published a signed, authenticated revocation record for this receipt, and its license class allows revocation — this receipt is revoked (spec §12).',
    },
    invalid_revocation_ignored: {
      label: 'Revocation',
      tone: 'warn',
      text: 'A revocation record for this receipt exists but was IGNORED: either it is not properly authenticated, or it tries to revoke a receipt whose license class forbids it (revocability “none”, or outside the refund window). The receipt stands (spec §12.2).',
    },
    // Reachable through the CLI, not through this page — the page supplies no
    // transfer view. It is in the catalogue for the same reason `revoked` is:
    // this file is the project's single copy of human wording for verify()'s
    // vocabulary, and a value that caps `ok` must never reach a reader as the
    // generic "no dedicated wording" fallback.
    transferred: {
      label: 'Revocation',
      tone: 'bad',
      text: 'This receipt was transferred away and no longer entitles whoever holds it: the issuer published an authenticated transfer record, itself proven to be in the log, and that record extinguished this copy (spec §17.3). The receipt issued to the new holder is the live one.',
    },
  },
  grant: {
    not_checked: {
      label: 'Preservation pledge',
      tone: 'neutral',
      text: 'This page does not evaluate preservation pledges — it hands the verifier no grant document, so there is nothing to judge. That is not the same as “this receipt has no pledge”: the signed grant a verifier has to read (spec §18.2) does not travel inside a .attest bundle, which carries the receipts, the key manifests, the licence and end-of-life TEXTS and any log proofs — not the grant document itself (spec §14.1). The CLI does that evaluation — attest verify --grant-view — and this page does not (spec §18.5). The same value also appears when a receipt names a pledge profile this verifier does not recognise — and that alone never makes the receipt invalid.',
    },
    none: {
      label: 'Preservation pledge',
      tone: 'neutral',
      text: 'This receipt carries no preservation pledge: nothing in it promises what becomes of your files if the seller shuts down (spec §18). Most receipts today are like this — it is a promise a seller chooses to make, not a defect when absent.',
    },
    dormant: {
      label: 'Preservation pledge',
      tone: 'good',
      text: 'A pledge is in force, it covers this purchase, and it has not opened: the seller is still trading, or the backstop date has not been proven to have passed (spec §18.4). Dormant is what a healthy promise looks like for the whole life of a working store — and, stated plainly because the spec states it plainly, a seller who simply vanishes without declaring anything, naming a successor or setting a backstop date leaves it dormant for good.',
    },
    activated: {
      label: 'Preservation pledge',
      tone: 'good',
      text: 'The sunset grant is open: either a cessation declaration authenticated, or an anchored proof placed the backstop date in the past, so the permission the pledge describes is now exercisable (spec §18.4). Whether the receipt itself is valid was decided above and is untouched by this — a grant is a permission that becomes exercisable, never a property of the signature (spec §10, §18.5).',
    },
    invalid_grant_ignored: {
      label: 'Preservation pledge',
      tone: 'warn',
      text: 'A grant document was supplied but does not belong to this receipt, or does not authenticate: its hash does not match the one sealed into the receipt, or its signature does not check out. It was ignored whole — nothing was granted, and the receipt itself is unaffected (spec §18.4).',
    },
  },
  publisher_authority: {
    not_checked: {
      label: 'Seller authorized by publisher',
      tone: 'neutral',
      text: 'This page does not evaluate publisher authorization — it hands the verifier no authorization document, so there is nothing to judge (spec §20.3). That is not the same as “this seller was not authorized”: a denial can only ever come from the publisher’s OWN signed manifest, and silence here means silence, not refusal. The CLI does that evaluation; this page does not.',
    },
    no_publisher_claim: {
      label: 'Seller authorized by publisher',
      tone: 'neutral',
      text: 'This receipt names no publisher separate from the seller, so there is no delegation to check (spec §20.4). Nothing is missing — most receipts are sold by whoever made the thing.',
    },
    self: {
      label: 'Seller authorized by publisher',
      tone: 'good',
      text: 'The seller and the publisher are the same party: whoever made this work sold it to you directly, so no third party had to authorize the sale (spec §20.4).',
    },
    authorized: {
      label: 'Seller authorized by publisher',
      tone: 'good',
      text: 'The publisher’s own signed authorization manifest lists this seller, and the receipt was issued inside the window that entry grants, with the permission and scope it covers (spec §20.2, §20.4). A later document that closes the window does not undo this: the question is always asked at the moment the receipt was issued, never against today (spec §20.2).',
    },
    unauthorized: {
      label: 'Seller authorized by publisher',
      tone: 'bad',
      text: 'The publisher’s own signed manifest does NOT authorize this seller for this receipt — the seller is absent from it, or outside the window, permission or scope it grants (spec §20.4). This is the one negative answer the protocol allows itself, and it is deliberately expensive: it requires an authenticated document that the caller’s own currency assertion names as the current one. It says the sale was not authorized; it does not say the receipt is forged, and the rows above stand on their own.',
    },
    unattested: {
      label: 'Seller authorized by publisher',
      tone: 'warn',
      text: 'Nothing settled the question: the evidence was absent, malformed, unauthenticated, stale, or two documents contradicted each other (spec §20.4). The protocol resolves every one of those to doubt and never to denial, so that anyone able to feed junk into this channel can buy exactly the doubt that already existed — and never a false accusation against a legitimate seller (spec §20.4, TM-77).',
    },
  },
  publisher_authority_trust: {
    not_checked: {
      label: 'Authorization signer',
      tone: 'neutral',
      text: 'No authorization document was offered to this page, so there is no signer to place (spec §20.3).',
    },
    verified: {
      label: 'Authorization signer',
      tone: 'good',
      text: 'The publisher’s key material was fetched over TLS from the publisher’s own domain — the strongest provenance attest defines, applied here to whoever signed the authorization (spec §20.4, §7.4). Like the pledge signer row, this reports where the keys came from and keeps its best available value even when the document beside it was rejected.',
    },
    unauthenticated_tofu: {
      label: 'Authorization signer',
      tone: 'warn',
      text: 'The publisher’s keys travelled with the authorization document instead of coming from the publisher’s own website — the math checks out, but nothing confirms who published those keys. Trust-on-first-use, reported as such (spec §20.4, §7.4).',
    },
    unverified_rotation: {
      label: 'Authorization signer',
      tone: 'warn',
      text: 'The publisher’s own documents disagree: two authenticated manifests claim the same version, or a later one broke the rule that an entry once published is closed rather than deleted and its settled windows never move (spec §20.2, §20.4 step 7). The publisher signed both, so the inconsistency is proven rather than alleged — and the verdict beside it falls back to what the documents still agree on.',
    },
    signer_mismatch: {
      label: 'Authorization signer',
      tone: 'warn',
      text: 'The authorization document authenticates, but the key that signed it does not belong to the publisher this receipt names (spec §20.4 step 6). A genuine signature from the wrong party settles nothing about this publisher’s intentions.',
    },
  },
  grant_trust: {
    not_checked: {
      label: 'Pledge signer',
      tone: 'neutral',
      text: 'No grant document was offered to this page, so there is no signer to place (spec §18.5).',
    },
    verified: {
      label: 'Pledge signer',
      tone: 'good',
      text: 'The publisher’s key material was fetched over TLS from the publisher’s own domain — the strongest provenance attest defines, applied here to whoever signed the pledge (spec §18.5, §7.4). This row reports where the signer’s keys came from and stays at its best available value even when the grant beside it was rejected: “verified” next to an ignored grant is normal, not a contradiction.',
    },
    unauthenticated_tofu: {
      label: 'Pledge signer',
      tone: 'warn',
      text: 'The publisher’s keys travelled with the grant document instead of coming from the publisher’s own website — the math checks out, but nothing confirms who published those keys. Trust-on-first-use, reported as such (spec §18.5, §7.4).',
    },
    unverified_rotation: {
      label: 'Pledge signer',
      tone: 'warn',
      text: 'The publisher’s manifest history has a gap, or a later grant version broke the ratchet that forbids narrowing an earlier promise, so continuity of the signer’s keys cannot be proven (spec §18.3, §18.5).',
    },
    signer_mismatch: {
      label: 'Pledge signer',
      tone: 'warn',
      text: 'The grant is well formed and genuinely signed — by a domain that is NOT the rights holder this receipt names. Someone else’s signature over someone else’s promise, which is why it grants nothing here (spec §18.1, §18.5).',
    },
  },
  transparency: {
    not_checked: {
      label: 'Transparency log',
      tone: 'neutral',
      text: 'No log evidence stands for this receipt: either the file carried none, or what it carried could not be resolved against the log this page pins. It is not a mark against the receipt — a receipt is valid on its signature, logged or not (spec §10). This one value covers a dozen different conditions; when one applies, it is named on this row.',
    },
    logged: {
      label: 'Transparency log',
      tone: 'good',
      text: 'The log this page pins holds this exact receipt: the inclusion proof checks out against a checkpoint signed by the log’s own keys (spec §10.2, steps 1–5). That proves publication in a public, append-only record — it does not make the receipt any more valid than its signature already did.',
    },
    equivocation_detected: {
      label: 'Transparency log',
      tone: 'bad',
      text: 'Two validly signed checkpoints for this log describe histories that cannot both be true: the log signed two incompatible versions of itself (spec §10.3). This is a hard verdict about the LOG, not about your receipt — whose own signature was judged above — and it is the one outcome here that must never be quietly filed under “not checked”. Keep this file exactly as it is and report it.',
    },
  },
  corroboration: {
    none: {
      label: 'Corroboration',
      tone: 'neutral',
      text: 'Nobody beyond the issuer vouches for this receipt having been published — the ordinary state, and nothing against the receipt (spec §10.1). Whenever the row above degrades, this one degrades with it: the reference implementation sets both in the same step (spec §10.2), so any condition named up there explains this row too.',
    },
    logged: {
      label: 'Corroboration',
      tone: 'good',
      text: 'The log’s own signed checkpoint covers this entry, so the log vouches for having published it — and that is the whole of it. This page pins no witness policy, so it does not examine cosignatures at all and reports none either way (spec §10.2, step 8). Separately, and not from anything checked here: attest operates this log itself and states in the log’s own README that no independent witness co-signs its checkpoints. Take that as the operator’s word, not as a result — and while it holds, a log serving two different histories to two different people could not be caught from this evidence alone (spec §10.3, §15).',
    },
    witnessed: {
      label: 'Corroboration',
      tone: 'good',
      text: 'A pinned co-signer with the corroboration role signed the checkpoint covering this entry, and its timestamped observation is on the record (spec §10.1, §11.4). That is the whole of the claim: an observation happened. It is NOT evidence that the co-signer is organizationally independent of the log — the spec forbids reading it that way and defines no way to establish independence at all (spec §10.1).',
    },
  },
  manifest_freshness: {
    not_checked: {
      label: 'Key manifest freshness',
      tone: 'neutral',
      text: 'Nobody offered proof that the issuer’s KEY MANIFEST — the document listing their signing keys, a separate thing from this receipt — is itself in the log. This page only ever presents the receipt’s own claim; the CLI can present a key-manifest claim when an issuer publishes one (spec §10.4).',
    },
  },
}

const FALLBACK: Record<Component, string> = {
  signature: 'Signature',
  schema: 'Schema',
  binding: 'Buyer binding',
  trust: 'Key trust',
  publisher_authority: 'Seller authorized by publisher',
  publisher_authority_trust: 'Authorization signer',
  revocation: 'Revocation',
  grant: 'Preservation pledge',
  grant_trust: 'Pledge signer',
  transparency: 'Transparency log',
  corroboration: 'Corroboration',
  manifest_freshness: 'Key manifest freshness',
}

// The three parametric values. Each carries a payload that a reader will
// misread if it is presented as the wrong KIND of quantity, so each says what
// its own number is: a feed timestamp, a block-header time, a tree size.
const PARAMETRIC: {
  component: Component
  prefix: string
  explain: (arg: string) => Explanation
}[] = [
  {
    component: 'revocation',
    prefix: 'not_revoked_as_of:',
    explain: (t) => ({
      label: 'Revocation',
      tone: 'good',
      text: `An authenticated revocation feed was consulted and no valid revocation matches this receipt — current as of ${t}, the newest signed timestamp in that feed (spec §12.3). Freshness is only as good as the feed.`,
    }),
  },
  {
    component: 'transparency',
    prefix: 'anchored_before:',
    explain: (t) => ({
      label: 'Transparency log',
      tone: 'good',
      text: `Stronger than logged: the checkpoint covering this entry is anchored in a Bitcoin block header this page pins, mined at ${t} — so the entry existed before that moment, and no later rewriting can move it (spec §11). That time comes from the pinned header, not from anyone’s clock, and it bounds WHEN the entry existed, not whether the receipt is valid.`,
    }),
  },
  {
    component: 'manifest_freshness',
    prefix: 'verified_as_of:',
    explain: (n) => ({
      label: 'Key manifest freshness',
      tone: 'good',
      text: `The issuer’s key manifest was in the log, unmodified, by the time the log had grown to ${n} entries (spec §10.4). That ${n} counts entries, not seconds: it places the manifest in the log’s order, not on a calendar. And it says nothing about those keys NOW — a later manifest version may since have marked one of them compromised.`,
    }),
  },
]

const COMPROMISE_RESCUE_APPLIED = 'compromise_rescue_applied'
const COMPROMISE_CUTOFF_UNANCHORED = 'compromise_cutoff_unanchored'
const COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT = 'compromise_rescue_requires_anchored_receipt'
const COMPROMISE_RESCUE_RECEIPT_AFTER_CUTOFF = 'compromise_rescue_receipt_after_cutoff'
const COMPROMISE_CUTOFF_CLAIM_IGNORED = 'compromise_cutoff_claim_ignored'
const COMPROMISE_MARKING_RETRACTED = 'compromise_marking_retracted'

const hasWarning = (result: VerificationResult | undefined, warning: string): boolean =>
  result?.warnings.includes(warning) ?? false

const hasCompromisedKeyError = (result: VerificationResult | undefined): boolean =>
  result?.errors.some((error) => /^key .+ is compromised$/.test(error)) ?? false

const RETRACTION_CONTEXT =
  'The issuer\u2019s own signed history also establishes that an earlier signed version of its key list declared this key compromised, while the higher-version list this verifier now trusts does not carry that marking. A compromise this verifier has already seen is not taken back by a later key list (spec v0.1 \u00a77.3).'

// The retraction is reported on leaves whose trust is "verified" too (41m, 41n,
// 41p, 41r): gating the story on `compromiseFloorVisible` alone would tell it
// only on the two leaves that also lost rotation continuity.
const withRetractionContext = (text: string, result: VerificationResult | undefined): string =>
  hasWarning(result, COMPROMISE_MARKING_RETRACTED) ? `${text} ${RETRACTION_CONTEXT}` : text

const compromiseFloorVisible = (result: VerificationResult | undefined): boolean =>
  result?.trust === 'unverified_rotation' && hasCompromisedKeyError(result)

function explainSignature(value: string, result: VerificationResult | undefined): Explanation | null {
  if (value === 'valid') {
    if (hasWarning(result, COMPROMISE_RESCUE_APPLIED)) {
      return {
        label: 'Signature',
        tone: 'good',
        text: withRetractionContext('This receipt’s exact signature was anchored in a public log strictly before the issuer’s compromise declaration was. The store cannot take back what the timeline already proves (spec v0.2 §19).', result),
      }
    }
    if (hasWarning(result, COMPROMISE_CUTOFF_UNANCHORED)) {
      return {
        label: 'Signature',
        tone: 'good',
        text: withRetractionContext('The signature checks out and this receipt has anchored standing, while no anchored compromise cutoff was established from the evidence this verifier holds — either none was offered, or what was offered could not establish one (spec v0.2 §19.3). A compromise declaration this verifier cannot date cannot invalidate a receipt it can. This is the weaker branch of the rescue: it rests on the absence of a datable declaration, not on proof that this receipt came first (spec v0.2 §19.6 items 4 and 6).', result),
      }
    }
    return null
  }
  if (value !== 'invalid' || !hasCompromisedKeyError(result)) return null
  if (hasWarning(result, COMPROMISE_RESCUE_RECEIPT_AFTER_CUTOFF)) {
    return {
      label: 'Signature',
      tone: 'bad',
      text: withRetractionContext('This key was declared compromised, and this receipt’s signature was not anchored strictly before that declaration was: it was anchored at the same moment or later. Equality is not proof of precedence — two things in the same block cannot be ordered — so the verifier fails closed (spec v0.2 §19.1).', result),
    }
  }
  if (compromiseFloorVisible(result) && hasWarning(result, COMPROMISE_MARKING_RETRACTED)) {
    // The verifier ESTABLISHED the retraction: say it as a fact, never deduce it.
    return {
      label: 'Signature',
      tone: 'bad',
      text: 'This key resolves to compromised for this verifier, and the issuer\u2019s own signed history contradicts its current key list: an earlier signed version of the list declared this key compromised, and the higher-version list this verifier now trusts does not carry that marking. A compromise this verifier has already seen is not taken back by a later key list. That is a statement about THIS verifier and not about everyone \u2014 a verifier that never saw the earlier evidence never sees the marking (spec v0.1 \u00a77.3, v0.2 \u00a719.6 item 5).',
    }
  }
  if (compromiseFloorVisible(result)) {
    return {
      label: 'Signature',
      tone: 'bad',
      text: 'This key resolves to compromised for this verifier, and continuity of the issuer’s manifest history could not be proven (see Key trust below). A compromise this verifier has already seen is not taken back by a later key list: if an earlier signed manifest declared this key compromised, a newer list that drops the marking does not restore it. That is a statement about THIS verifier and not about everyone — a verifier that never saw the earlier manifest never sees the marking (spec v0.1 §7.3, v0.2 §19.6 item 5).',
    }
  }
  return {
    label: 'Signature',
    tone: 'bad',
    text: withRetractionContext('This key was declared compromised by its issuer, and this verifier holds no anchored proof of THIS receipt’s own signature predating that declaration — an anchored time that belongs to some other claim, such as the issuer’s key manifest, does not stand in for it. The receipt may be genuine; nothing here can tell, so the verifier fails closed (spec v0.1 §7.3, v0.2 §19).', result),
  }
}

function explainTrust(value: string, result: VerificationResult | undefined): Explanation | null {
  if (value !== 'unverified_rotation' || !compromiseFloorVisible(result)) return null
  if (hasWarning(result, COMPROMISE_MARKING_RETRACTED)) {
    return {
      label: 'Key trust',
      tone: 'warn',
      text: 'The issuer rewrote the history of its own keys: an earlier signed manifest marks this receipt\u2019s signing key compromised, and a later, higher-version list drops the marking. It changes nothing here: a compromise this verifier has seen stays (spec v0.1 \u00a77.3).',
    }
  }
  return {
    label: 'Key trust',
    tone: 'warn',
    text: 'Continuity of the issuer’s key manifest history could not be proven, and this receipt’s signing key resolves to compromised. One shape this takes is an issuer rewriting the history of its own keys — an earlier signed manifest marks a key compromised, a later list drops the marking — and it changes nothing here: a compromise this verifier has seen stays. Other gaps in the history produce this same value, and all of them leave key provenance in doubt (spec v0.1 §7.3).',
  }
}

export function explain(
  component: Component,
  value: string,
  result?: VerificationResult,
): Explanation {
  if (component === 'signature') {
    const signature = explainSignature(value, result)
    if (signature) return signature
  }
  if (component === 'trust') {
    const trust = explainTrust(value, result)
    if (trust) return trust
  }
  const hit = CATALOG[component][value]
  if (hit) return hit
  for (const p of PARAMETRIC) {
    if (p.component === component && value.startsWith(p.prefix)) {
      return p.explain(value.slice(p.prefix.length))
    }
  }
  return {
    label: FALLBACK[component],
    tone: 'neutral',
    text: `This verifier does not have dedicated wording for “${value}” — see the raw result below and spec §11.1 for the normative meaning.`,
  }
}

export function explainVerdict(ok: boolean): Explanation {
  return ok
    ? {
        label: 'Receipt verifies',
        tone: 'good',
        text: 'Signature valid, schema valid, not revoked as far as this check could see, and no errors — the four-gate “ok” of spec §11.1.',
      }
    : {
        label: 'Receipt does NOT verify',
        tone: 'bad',
        text: 'At least one of the four gates failed — the rows below show exactly which one and why (spec §11.1).',
      }
}

// --------------------------------------------------------------------------
// Warning → component attribution.
//
// `not_checked` is overloaded: on `transparency`/`corroboration` roughly a
// dozen distinct evidence failures collapse into the same pair of values, and
// on `grant` it means both "no evidence was offered" and "unrecognised pledge
// profile". The distinction lives ONLY in `warnings[]`, which this page used
// to render as one flat list with no link back to the row that produced it —
// so a reader saw a neutral row and, somewhere below, a token they had no way
// to connect to it. Attribution is what makes the row honest.
//
// The tokens are a cross-language wire surface (verifiers/ts/src/messages.ts,
// mirrored byte-for-byte from the Python reference): matched exactly, never
// paraphrased. A warning that matches nothing keeps its old home in the flat
// list — attribution may never make a warning disappear.
// --------------------------------------------------------------------------
const EXACT: Record<string, Component> = {
  // verify.py's Stage 2 integration + transparency.py's evaluation tokens.
  transparency_config_missing: 'transparency',
  transparency_claim_unresolvable: 'transparency',
  evidence_invalid: 'transparency',
  entry_invalid: 'transparency',
  transparency_entry_mismatch: 'transparency',
  checkpoint_invalid: 'transparency',
  checkpoint_verification_failed: 'transparency',
  leaf_index_invalid: 'transparency',
  tree_size_invalid: 'transparency',
  tree_size_mismatch: 'transparency',
  inclusion_proof_invalid: 'transparency',
  inclusion_proof_too_long: 'transparency',
  prior_checkpoint_invalid: 'transparency',
  consistency_proof_missing: 'transparency',
  consistency_proof_invalid: 'transparency',
  consistency_proof_too_long: 'transparency',
  log_equivocation_detected: 'transparency',
  anchors_invalid: 'transparency',
  anchor_time_invalid: 'transparency',
  anchor_note_only: 'transparency',
  post_horizon_unanchored: 'transparency',
  evidence_evaluation_failed: 'transparency',
  // Both speak about who vouches, not about whether the entry is there.
  corroboration_requires_rotation_chain: 'corroboration',
  witness_independence_not_established: 'corroboration',
  // Stage 3 transfer + G5's logged-revocation deadline: all of them qualify
  // whether a revocation-class record counts, which is `revocation`'s row.
  revocation_unlogged_deadline: 'revocation',
  transferred_revocation_unbacked: 'revocation',
  transfer_record_unlogged: 'revocation',
  transfer_not_yet_transferable: 'revocation',
  transfer_double_assignment_conflict: 'revocation',
  // v0.2 §19 compromise-cutoff warnings qualify the signature row: they say
  // why a compromised-key signature was rescued, rejected, or ignored.
  [COMPROMISE_RESCUE_APPLIED]: 'signature',
  [COMPROMISE_CUTOFF_UNANCHORED]: 'signature',
  [COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT]: 'signature',
  [COMPROMISE_RESCUE_RECEIPT_AFTER_CUTOFF]: 'signature',
  [COMPROMISE_CUTOFF_CLAIM_IGNORED]: 'signature',
  [COMPROMISE_MARKING_RETRACTED]: 'signature',
  // §18.5's ten literals. Nine describe the grant; one describes its SIGNER,
  // and the spec pairs it with `grant_trust: "signer_mismatch"` explicitly.
  grant_narrowing_ignored: 'grant',
  grant_unanchored: 'grant',
  grant_scope_uncovered: 'grant',
  grant_commitment_mismatch: 'grant',
  grant_declaration_ignored: 'grant',
  grant_activated_by_successor: 'grant',
  grant_pledge_type_unknown: 'grant',
  grant_legal_text_changed: 'grant',
  grant_signer_not_publisher: 'grant_trust',
  // §20's four literals. Three describe the authorization; one describes its
  // SIGNER, and the spec pairs it with `publisher_authority_trust:
  // "signer_mismatch"` exactly as §18.5 does for the grant.
  publisher_claim_unattested: 'publisher_authority',
  publisher_not_authorizing_issuer: 'publisher_authority',
  authorization_invalid_ignored: 'publisher_authority',
  authorization_signer_not_publisher: 'publisher_authority_trust',
  // Emitted from the block that computes `trust` and can itself force
  // `unverified_rotation` (verify.ts, G2/G3/G6 manifest currency).
  artifact_manifest_unversioned: 'trust',
  artifact_manifest_unauthenticated: 'trust',
  artifact_manifest_issuer_mismatch: 'trust',
}

// Free-text warnings that interpolate a value. Order matters only in that the
// first match wins; the families do not overlap.
const PATTERNS: { match: RegExp; component: Component }[] = [
  // "key <kid> is retired" is genuinely two-sided: it fires in step 3's key
  // checks, immediately before the Ed25519 verification (v0.1 §11 step 3), and
  // it is also issuer key hygiene, which is `trust`'s territory. It changes
  // neither value. Placed beside the signature it made, because that is the
  // sentence a reader can act on — the math holds, the key is on its way out
  // — and both rows sit under the same question either way.
  { match: /^key .+ is retired$/, component: 'signature' },
  { match: /^revocation (record|view) /, component: 'revocation' },
  // anchor.py / tlog.py diagnostics: prose rather than tokens, all of them
  // about one untrusted evidence bundle.
  { match: /^evidence\./, component: 'transparency' },
  { match: /^proof\[\d+\]: /, component: 'transparency' },
  { match: /^ots /, component: 'transparency' },
  { match: /^unknown (ots op|proof kind) /, component: 'transparency' },
  { match: /^rfc3161 /, component: 'transparency' },
  { match: /^header_hash is not in policy/, component: 'transparency' },
  { match: /^pinned header /, component: 'transparency' },
  { match: /^entry scalar exceeds /, component: 'transparency' },
]

/** The component a warning belongs beside, or null when it belongs to none.
 *
 * Null is a real answer, not a gap, and three families rely on it. The content
 * warnings (`license.drm is drm-bound`, `unknown payload field: ...`) come out
 * of a pass that is independent of the crypto pipeline and move no component's
 * value (v0.1 §11.2). `mixed_keyset_active_ed_only_sibling` has nowhere to go
 * by normative statement: §13.1 says no result field classifies hybrid
 * strength, "because none exists". And `grant_commitment_divergence` is
 * emitted from the signed payload alone, whether or not any grant evidence was
 * supplied (§18.2), so hanging it under the pledge row would credit an
 * evaluation that may never have run. Each of them keeps its place in the flat
 * list, where it makes a claim about the receipt rather than about a row.
 */
export function attributeWarning(warning: string): Component | null {
  const exact = EXACT[warning]
  if (exact) return exact
  for (const p of PATTERNS) if (p.match.test(warning)) return p.component
  return null
}
