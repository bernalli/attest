import type { Disclosure } from 'attest-verifier'
import { loadsStrict } from 'attest-verifier'
import {
  intake, declinedForSize, trustStoreFromManifestBytes,
  type Refusal, type VerifyJob,
} from '../../site/src/intake.js'
import {
  runVerify, verifyOptionsFor, railNotice, NO_RAILS, type Rails,
} from '../../site/src/run.js'
import { renderRejection, renderDeclined, renderVerifyFailure } from '../../site/src/render.js'
import { LOG_KEYS, ANCHOR_POLICY } from '../../site/src/trusted-log.js'
import { b64uDecode } from '../../site/src/b64u.js'
import { renderDesktopCard } from './card.js'

/**
 * The wiring over the static shell in `index.html`.
 *
 * The shell — including the failure banner and the disabled dropzone — is markup the
 * browser parses without executing anything, and this module clears both as its LAST
 * action, once the wiring above it cannot fail. The ordering is the point: clearing
 * first would announce a working app and then throw halfway through.
 *
 * The banner cannot live here. An earlier version built the shell from a template
 * literal in this file, which made the failsafe circular — the banner did not exist
 * until the script had run, so the one case it exists for produced an empty page.
 *
 * No sample loader: fetching one would be a network request, and this app must never
 * make one.
 */

// Told apart from a merely unreadable file: this one IS an attest artifact, just the
// wrong one of the THREE things this project calls a "manifest" — the container a bundle
// keeps inside it (`key_manifests`), the single key list this zone wants (`issuer`,
// `keys`), and a pre-built trust store (`manifests`, `chains`). Answering "invalid" to
// someone who extracted the file named `manifest` from their own bundle — the most
// natural thing to try — teaches them the system is broken rather than that they picked
// the wrong file.
//
// Decided with `loadsStrict`, the SAME parser `trustStoreFromManifestBytes` refused the
// bytes with. An earlier version re-read them with `JSON.parse`, which accepts what
// canonical JSON does not, so the two disagreed and the message described a document the
// drop zone had never seen. Measured on four inputs: a real key list carrying a UTF-8
// BOM, a float, a duplicate field name, or one bad byte was refused with "not an attest
// key list (expected JSON with issuer and keys)" — of a file that had both.
function describeManifestRefusal(bytes: Uint8Array): string {
  // Before parsing, because a zip is never text: this is the file the `key_manifests`
  // branch below sends people to fetch, and answering "that is not JSON" to someone who
  // just did what this page told them is the app contradicting itself.
  if (bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b)
    return (
      'That is a whole .attest bundle, not a key list on its own. Drop it on the receipt ' +
      'area above instead — a bundle already carries the seller’s key list inside it, and ' +
      'this page will take the right one out.'
    )

  let parsed: unknown
  try {
    parsed = loadsStrict(bytes)
  } catch {
    // The lenient parser gets a say about which MESSAGE to show, never about what to
    // accept. The decode is inside the try because an oversized buffer throws RangeError.
    let isJson = true
    try {
      JSON.parse(new TextDecoder().decode(bytes))
    } catch {
      isJson = false
    }
    if (!isJson)
      return 'That file is not JSON, so it cannot be a key list. The seller publishes one as a .json file; a bundle also carries one inside it.'
    return (
      'That file is JSON, but not the exact form attest signs and checks, so the strict ' +
      'reader refused it. The usual causes are a byte-order mark an editor added when the ' +
      'file was re-saved, a repeated field name, or a number written with a decimal point. ' +
      'Ask the seller for the file exactly as they published it, or take it out of the ' +
      '.attest bundle rather than saving a copy of it.'
    )
  }

  // `hasOwnProperty`, not `in`: these keys are attacker-supplied and it is the field's own
  // presence that names the file, never one inherited from a polluted prototype. Same rule
  // `intake.ts` already states for `proofFor`.
  const has = (key: string): boolean =>
    typeof parsed === 'object' &&
    parsed !== null &&
    !Array.isArray(parsed) &&
    Object.prototype.hasOwnProperty.call(parsed, key)

  if (has('key_manifests'))
    return (
      'That is the file a bundle keeps INSIDE it, which holds a list of key lists ' +
      '(its "key_manifests" field) — not a single key list. Drop the whole .attest ' +
      'bundle instead and this page will take the right one out of it, or hand over ' +
      'one entry of that list on its own.'
    )
  if (has('manifests') || has('artifact_manifests'))
    return (
      'That is an already-built trust store — key lists indexed by seller (its ' +
      '"manifests" field), the shape a developer hands a verifier. This zone wants ONE ' +
      'seller’s key list: the object with "issuer" and "keys" that sits inside it.'
    )
  if (has('issuer') && !has('keys'))
    return 'That file names an issuer but carries no "keys" list, so there is nothing in it to check a signature against.'
  if (has('keys') && !has('issuer'))
    return 'That file carries a "keys" list but never says which issuer the keys belong to, so this page cannot tell whose they are.'
  if (has('issuer') && has('keys'))
    return (
      'That file has "issuer" and "keys" but not in the shape a key list needs: "issuer" ' +
      'has to be the seller’s domain as text and "keys" has to be a list. Ask the seller ' +
      'for the file exactly as they published it.'
    )
  return 'That file is not an attest key list (expected JSON with "issuer" and "keys").'
}

export interface DesktopApp {
  handleBytes(fileName: string, bytes: Uint8Array): void
  handleManifestBytes(bytes: Uint8Array): void
  applyDisclosure(): void
  clearRails(): void
}

export function initDesktopApp(doc: Document): DesktopApp {
  const byId = <T extends HTMLElement>(id: string): T => {
    const node = doc.getElementById(id)
    if (!node) throw new Error(`desktop shell: missing #${id}`)
    return node as T
  }
  const dropzone = byId<HTMLElement>('dropzone')
  const fileInput = byId<HTMLInputElement>('file-input')
  const manifestZone = byId<HTMLElement>('manifest-zone')
  const manifestInput = byId<HTMLInputElement>('manifest-input')
  const manifestPick = byId<HTMLButtonElement>('manifest-pick')
  const bindingIdentifier = byId<HTMLInputElement>('binding-identifier')
  const bindingType = byId<HTMLSelectElement>('binding-type')
  const bindingSalt = byId<HTMLInputElement>('binding-salt')
  const bindingApply = byId<HTMLButtonElement>('binding-apply')
  const clearFeedsBtn = byId<HTMLButtonElement>('clear-feeds')
  const results = byId<HTMLElement>('results')

  let currentJobs: VerifyJob[] = []
  // The four evidence rails of v0.1 §14.3, one slot each, replaced and never
  // merged. Same machine as the site's, over the SAME `intake`: the rails are a
  // property of the file format, not of the shell that reads it, and two shells
  // that disagreed about which files they recognize would be two verifiers.
  //
  // They outlive the receipts on screen deliberately. Whoever runs this app
  // supplies the seller's evidence once and then opens receipts against it; a
  // rail emptied by the arrival of a receipt is a rail nobody can keep.
  let currentRails: Rails = { ...NO_RAILS }
  // The binding proof the reader has already given, kept as STATE rather than as
  // an argument that lives for one render. Two of the paths below re-render the
  // same cards without a new file — a rail drop and Clear feeds — and passing
  // `null` there re-verifies with no disclosure, which prints "Nobody attempted
  // to prove who this receipt belongs to" over a proof the reader just supplied.
  // `main.ts` has held this state since it had a bench to hold it for; the two
  // shells run one `intake` and must not disagree about one gesture.
  let currentDisclosure: Disclosure | null = null
  let currentNotices: string[] = []
  let pendingEnvelope: { bytes: Uint8Array; fileName: string; label: string } | null = null
  // The name the OS handed over with the bytes currently on screen. Kept here rather
  // than on the job because `intake` labels a job from the SIGNED payload: the two are
  // different strings saying different things, and the card must not confuse them.
  let droppedFileName = ''

  const message = (text: string): HTMLElement => {
    const p = doc.createElement('p')
    p.className = 'notice'
    p.textContent = text
    return p
  }

  // Deliberately NOT a `.notice`. A notice is about the file just dropped and
  // goes away with it; this says what the verdicts below were computed against,
  // and it is owed for as long as they are on screen.
  const railLine = (text: string): HTMLElement => {
    const p = doc.createElement('p')
    p.className = 'rails'
    p.textContent = text
    return p
  }

  function renderJobs(disclosure: Disclosure | null, notice?: string): void {
    results.replaceChildren(
      // A transient notice — a mistyped salt, an empty identifier — rides ABOVE the cards
      // rather than replacing them. Taking the verdict off the screen because an optional
      // field was typed wrong is the same harm the per-job catch below exists to prevent.
      ...(notice === undefined ? [] : [message(notice)]),
      ...currentNotices.map(message),
      // What each rail is holding, in numbers and fixed labels only. Owed
      // whenever there are verdicts, because §14.3 requires the surface to say
      // that a rail with no file was not consulted — and the result cannot,
      // reporting `unknown` for that and for an empty feed alike. Never the
      // presence of a file as proof that anything in it verified (C-86).
      ...(currentJobs.length > 0
        ? [
            railLine(
              (['revocation', 'transfer', 'compromise', 'revocationEvidence'] as const)
                .map((rail) => railNotice(rail, currentRails[rail]))
                .join(' · '),
            ),
          ]
        : []),
      // Per job, never per batch: the verifier's trusted-config validation throws by
      // design, and an exception escaping this map would abandon the whole replace —
      // leaving the previous results on screen, which is the worst outcome available.
      // One receipt this app cannot check must not take the others down with it.
      ...currentJobs.map((job) => {
        try {
          return renderDesktopCard(
            job,
            runVerify(job.envelopeBytes, job.trustStore, currentRails.revocation, disclosure, {
              transparency: job.transparency,
              logKeys: LOG_KEYS,
              anchorPolicy: ANCHOR_POLICY,
              ...verifyOptionsFor(currentRails),
            }),
            droppedFileName,
            { revocationFeedConsulted: currentRails.revocation !== null },
          )
        } catch (e) {
          return renderVerifyFailure(job.label, e instanceof Error ? e.message : String(e))
        }
      }),
    )
  }

  /** One refusal, one register — for the reader below and for the admission
   * boundary at the drop target alike. A container this app DECLINED to read
   * gets §14.4's neutral register; everything else gets the rejection. */
  function showRefusal(r: Refusal): void {
    currentJobs = []
    currentNotices = []
    // Cleared here too, or a half-finished handover survives its own refusal: measured,
    // a later manifest resurrected the earlier receipt and replaced the bearer-file
    // warning with its verdict.
    pendingEnvelope = null
    manifestZone.hidden = true
    results.replaceChildren(
      r.declined === true ? renderDeclined(r.reason) : renderRejection(r.reason),
    )
  }

  function handleBytes(fileName: string, bytes: Uint8Array): void {
    const r = intake(fileName, bytes)
    if (r.kind === 'rejected') {
      if (r.rail !== undefined) {
        // §14.3: a refused evidence file is a refusal of THAT file and changes
        // nothing else. The receipts on screen stay, their verdicts stay, and
        // the rails keep whatever they held — clearing them would punish the
        // reader for a typo in a file that has nothing to do with the receipt.
        results.prepend(renderRejection(r.reason))
        return
      }
      // The two pieces of state `showRefusal` cannot reach: the name belongs to
      // the file that was just dropped, and a disclosure given for the PREVIOUS
      // receipt must not outlive it — a refusal leaves nothing of it on screen,
      // and a proof still held would be a claim about a file that is gone.
      droppedFileName = fileName
      currentDisclosure = null
      showRefusal(r)
      return
    }
    if (r.kind === 'view') {
      // Replaced, never merged, and the cards on screen stay exactly where they
      // are — only their verdicts are recomputed against the new rail.
      currentRails = { ...currentRails, [r.rail]: r.value } as Rails
      if (currentJobs.length === 0) {
        // With no cards, `renderJobs` is a `replaceChildren` over an empty list:
        // measured, it erased the `.private.attest` refusal — the one sentence
        // this app most needs to leave on screen — and the key-list handover
        // instruction, while the handover zone stayed open. A rail file changes
        // that rail and nothing else (§14.3).
        results.prepend(railLine(railNotice(r.rail, r.value)))
        return
      }
      renderJobs(currentDisclosure)
      return
    }
    // Only now: a rail file is not the file the card is about, and writing its
    // name here would print it under "File you dropped" beside a verdict
    // computed over entirely different bytes.
    droppedFileName = fileName
    currentNotices = r.notices ?? []
    if (r.kind === 'needs-manifest') {
      currentJobs = []
      currentDisclosure = null
      // `fileName` is the parameter, not anything intake returns: intake's own `label`
      // is the signed receipt id.
      pendingEnvelope = { bytes: r.envelopeBytes, fileName, label: r.label }
      manifestZone.hidden = false
      results.replaceChildren(
        ...currentNotices.map(message),
        message(
          'This receipt does not carry the seller’s key list. Drop that file below, or ' +
            'open the whole .attest bundle instead — a bundle carries the key list with it.',
        ),
      )
      return
    }
    pendingEnvelope = null
    manifestZone.hidden = true
    currentJobs = r.jobs
    // A new receipt is not the receipt the previous proof was for: the disclosure
    // is dropped WITH the jobs it applied to, never carried across them.
    currentDisclosure = null
    renderJobs(currentDisclosure)
  }

  function handleManifestBytes(bytes: Uint8Array): void {
    if (!pendingEnvelope) return
    const trustStore = trustStoreFromManifestBytes(bytes)
    if (!trustStore) {
      results.replaceChildren(...currentNotices.map(message), message(describeManifestRefusal(bytes)))
      return
    }
    droppedFileName = pendingEnvelope.fileName
    currentJobs = [
      {
        label: pendingEnvelope.label,
        envelopeBytes: pendingEnvelope.bytes,
        trustStore,
        transparency: null,
      },
    ]
    pendingEnvelope = null
    manifestZone.hidden = true
    currentDisclosure = null
    renderJobs(currentDisclosure)
  }

  function applyDisclosure(): void {
    if (currentJobs.length === 0) {
      // Silence is the one answer a verifier may never give: a reader who pressed Check
      // and saw nothing cannot tell "nothing is loaded" from "this page is dead", which
      // is the ambiguity the boot banner exists to remove.
      results.replaceChildren(message('There is no receipt open to check yet. Drop one above first.'))
      return
    }
    let salt: Uint8Array
    try {
      salt = b64uDecode(bindingSalt.value.trim())
    } catch {
      // The previously proven binding stays: a typo in the salt field is not a
      // retraction of a proof that already succeeded, and wiping it would make the
      // Binding row say that nobody ever tried.
      renderJobs(
        currentDisclosure,
        'That salt is not valid base64url (unpadded). Copy it exactly from your ' +
          '.private.attest sidecar.',
      )
      return
    }
    if (bindingIdentifier.value.trim() === '') {
      renderJobs(
        currentDisclosure,
        'Type the email address or account id this receipt was issued to — checking ' +
          'against an empty one proves nothing.',
      )
      return
    }
    currentDisclosure = {
      identifier: bindingIdentifier.value.trim(),
      identifier_type: bindingType.value,
      salt,
    }
    renderJobs(currentDisclosure)
  }

  // §14.3 makes a rail's slot the operator's own configuration rather than
  // something a dropped receipt may change, so the only way back to "not
  // consulted" is an explicit gesture. All four at once: four buttons would let
  // someone believe they had cleared the feeds while one still held a file.
  function clearRails(): void {
    currentRails = { ...NO_RAILS }
    if (currentJobs.length === 0) {
      results.prepend(railLine('Every evidence feed is back to “not consulted”.'))
      return
    }
    renderJobs(currentDisclosure)
  }

  const readFile = (file: File, sink: (name: string, bytes: Uint8Array) => void): void => {
    // The size is metadata: asking for it reads no byte of the file, so a container
    // over §14.4's floor is refused before `arrayBuffer()` brings a copy of it into
    // this process. This artifact runs from a file:// URL on whatever machine a
    // holder still has years from now, which is the machine least able to afford a
    // copy it was never going to read.
    const refusal = declinedForSize(file.size)
    if (refusal !== null) {
      showRefusal(refusal)
      return
    }
    void file
      .arrayBuffer()
      .then((buf) => sink(file.name, new Uint8Array(buf)))
      .catch(() => {
        // A read that fails — the file moved, the volume went away, the OS refused — must
        // not leave the page silent. Measured before this existed: the results pane stayed
        // empty and the rejection went unhandled, which is the boot-failsafe scenario
        // arriving after boot, where the banner is already gone and cannot say anything.
        // The file's own name is deliberately NOT quoted back: it is attacker-chosen text
        // and nothing here needs it.
        currentJobs = []
        currentNotices = []
        pendingEnvelope = null
        manifestZone.hidden = true
        results.replaceChildren(
          message(
            'This page could not read that file, so nothing was checked. It may have been ' +
              'moved or renamed after you picked it — try opening it again.',
          ),
        )
      })
  }

  dropzone.addEventListener('click', () => fileInput.click())
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      fileInput.click()
    }
  })
  dropzone.addEventListener('dragover', (e) => e.preventDefault())
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault()
    const file = e.dataTransfer?.files?.[0]
    if (file) readFile(file, handleBytes)
  })
  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0]
    if (file) readFile(file, handleBytes)
    fileInput.value = ''
  })
  manifestPick.addEventListener('click', () => manifestInput.click())
  manifestInput.addEventListener('change', () => {
    const file = manifestInput.files?.[0]
    if (file) readFile(file, (_name, bytes) => handleManifestBytes(bytes))
    manifestInput.value = ''
  })
  bindingApply.addEventListener('click', applyDisclosure)
  clearFeedsBtn.addEventListener('click', clearRails)

  // Last, and only once the wiring above cannot fail: clearing the banner is this app's
  // claim that it is working, so it must be the final step rather than the first.
  doc.getElementById('boot-failsafe')?.remove()
  dropzone.removeAttribute('aria-disabled')

  return { handleBytes, handleManifestBytes, applyDisclosure, clearRails }
}
