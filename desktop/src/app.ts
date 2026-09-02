import type { Disclosure } from 'attest-verifier'
import { loadsStrict } from 'attest-verifier'
import { intake, trustStoreFromManifestBytes, type VerifyJob } from '../../site/src/intake.js'
import { runVerify } from '../../site/src/run.js'
import { renderRejection, renderVerifyFailure } from '../../site/src/render.js'
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
  const results = byId<HTMLElement>('results')

  let currentJobs: VerifyJob[] = []
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

  function renderJobs(disclosure: Disclosure | null, notice?: string): void {
    results.replaceChildren(
      // A transient notice — a mistyped salt, an empty identifier — rides ABOVE the cards
      // rather than replacing them. Taking the verdict off the screen because an optional
      // field was typed wrong is the same harm the per-job catch below exists to prevent.
      ...(notice === undefined ? [] : [message(notice)]),
      ...currentNotices.map(message),
      // Per job, never per batch: the verifier's trusted-config validation throws by
      // design, and an exception escaping this map would abandon the whole replace —
      // leaving the previous results on screen, which is the worst outcome available.
      // One receipt this app cannot check must not take the others down with it.
      ...currentJobs.map((job) => {
        try {
          return renderDesktopCard(
            job,
            runVerify(job.envelopeBytes, job.trustStore, null, disclosure, {
              transparency: job.transparency,
              logKeys: LOG_KEYS,
              anchorPolicy: ANCHOR_POLICY,
            }),
            droppedFileName,
          )
        } catch (e) {
          return renderVerifyFailure(job.label, e instanceof Error ? e.message : String(e))
        }
      }),
    )
  }

  function handleBytes(fileName: string, bytes: Uint8Array): void {
    droppedFileName = fileName
    const r = intake(fileName, bytes)
    if (r.kind === 'rejected') {
      currentJobs = []
      currentNotices = []
      // Cleared here too, or a half-finished handover survives its own refusal: measured,
      // a later manifest resurrected the earlier receipt and replaced the bearer-file
      // warning with its verdict.
      pendingEnvelope = null
      manifestZone.hidden = true
      results.replaceChildren(renderRejection(r.reason))
      return
    }
    currentNotices = r.notices ?? []
    if (r.kind === 'needs-manifest') {
      currentJobs = []
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
    renderJobs(null)
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
    renderJobs(null)
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
      renderJobs(
        null,
        'That salt is not valid base64url (unpadded). Copy it exactly from your ' +
          '.private.attest sidecar.',
      )
      return
    }
    if (bindingIdentifier.value.trim() === '') {
      renderJobs(
        null,
        'Type the email address or account id this receipt was issued to — checking ' +
          'against an empty one proves nothing.',
      )
      return
    }
    renderJobs({
      identifier: bindingIdentifier.value.trim(),
      identifier_type: bindingType.value,
      salt,
    })
  }

  const readFile = (file: File, sink: (name: string, bytes: Uint8Array) => void): void => {
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

  // Last, and only once the wiring above cannot fail: clearing the banner is this app's
  // claim that it is working, so it must be the final step rather than the first.
  doc.getElementById('boot-failsafe')?.remove()
  dropzone.removeAttribute('aria-disabled')

  return { handleBytes, handleManifestBytes, applyDisclosure }
}
