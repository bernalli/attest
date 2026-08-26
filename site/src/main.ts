import type { Disclosure } from 'attest-verifier'
import { intake, trustStoreFromManifestBytes, type VerifyJob } from './intake.js'
import { runVerify } from './run.js'
import { renderResult, renderRejection } from './render.js'
import { b64uDecode } from './b64u.js'
import { loadSample } from './sample.js'

export interface AppHandle {
  handleBytes(fileName: string, bytes: Uint8Array): void
  handleManifestBytes(bytes: Uint8Array): void
  applyDisclosure(): void
  loadSampleBundle(): Promise<void>
}

function message(doc: Document, text: string): HTMLElement {
  const p = doc.createElement('p')
  p.className = 'notice'
  p.textContent = text
  return p
}

export function initApp(doc: Document): AppHandle {
  const byId = <T extends HTMLElement>(id: string): T => {
    const node = doc.getElementById(id)
    if (!node) throw new Error(`missing #${id}`)
    return node as T
  }
  const dropzone = byId<HTMLElement>('dropzone')
  const fileInput = byId<HTMLInputElement>('file-input')
  const manifestZone = byId<HTMLElement>('manifest-zone')
  const manifestInput = byId<HTMLInputElement>('manifest-input')
  const bindingIdentifier = byId<HTMLInputElement>('binding-identifier')
  const bindingType = byId<HTMLSelectElement>('binding-type')
  const bindingSalt = byId<HTMLInputElement>('binding-salt')
  const bindingApply = byId<HTMLButtonElement>('binding-apply')
  const loadSampleBtn = byId<HTMLButtonElement>('load-sample')
  const results = byId<HTMLElement>('results')

  let currentJobs: VerifyJob[] = []
  let currentNotices: string[] = []
  let pendingEnvelope: { bytes: Uint8Array; fileName: string } | null = null

  // Notices are prepended on every render, not written once: `renderJobs` runs
  // again on every disclosure and on the manifest handover, and a warning that
  // disappears the moment the reader interacts with the page is a warning that
  // was never really there.
  // The evidence channel carries ONLY what came out of the dropped file:
  // `transparency`, the §10.2 bundle a `proofs/` member held. The other
  // members of VerifyTransparencyOptions — `logKeys`, `anchorPolicy`,
  // `witnessPolicy` — are the verifier's trusted, out-of-band configuration
  // and are deliberately absent: this page pins no log. Passing evidence
  // without them is not a gap being papered over, it is the honest reading —
  // verify() answers `not_checked` and says `transparency_config_missing`,
  // instead of the silence a caller that never opened the channel would get.
  function renderJobs(disclosure: Disclosure | null): void {
    results.replaceChildren(
      ...currentNotices.map((text) => message(doc, text)),
      ...currentJobs.map((job) =>
        renderResult(
          job.label,
          runVerify(job.envelopeBytes, job.trustStore, null, disclosure, { transparency: job.transparency }),
        ),
      ),
    )
  }

  function handleBytes(fileName: string, bytes: Uint8Array): void {
    const r = intake(fileName, bytes)
    if (r.kind === 'rejected') {
      currentJobs = []
      currentNotices = []
      manifestZone.hidden = true
      results.replaceChildren(renderRejection(r.reason))
      return
    }
    currentNotices = r.notices ?? []
    if (r.kind === 'needs-manifest') {
      currentJobs = []
      pendingEnvelope = { bytes: r.envelopeBytes, fileName: r.fileName }
      manifestZone.hidden = false
      results.replaceChildren(
        ...currentNotices.map((text) => message(doc, text)),
        message(doc, 'This receipt has no issuer manifest embedded. Drop the issuer’s key-manifest JSON below (or verify a full .attest bundle instead, which carries it).'),
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
      results.replaceChildren(
        ...currentNotices.map((text) => message(doc, text)),
        message(doc, 'That file is not an attest key manifest (expected JSON with "issuer" and "keys").'),
      )
      return
    }
    currentJobs = [{ label: pendingEnvelope.fileName, envelopeBytes: pendingEnvelope.bytes, trustStore, transparency: null }]
    pendingEnvelope = null
    manifestZone.hidden = true
    renderJobs(null)
  }

  function applyDisclosure(): void {
    if (currentJobs.length === 0) return
    let salt: Uint8Array
    try {
      salt = b64uDecode(bindingSalt.value.trim())
    } catch {
      results.replaceChildren(
        ...currentNotices.map((text) => message(doc, text)),
        message(doc, 'That salt is not valid base64url (unpadded). Copy it exactly from your .private.attest sidecar.'),
      )
      return
    }
    renderJobs({ identifier: bindingIdentifier.value.trim(), identifier_type: bindingType.value, salt })
  }

  async function loadSampleBundle(): Promise<void> {
    const sample = await loadSample()
    bindingIdentifier.value = sample.binding.identifier
    bindingType.value = sample.binding.identifier_type
    bindingSalt.value = sample.binding.salt_b64u
    handleBytes('demo.attest', sample.bytes)
  }

  const readFile = (file: File, sink: (name: string, bytes: Uint8Array) => void): void => {
    void file.arrayBuffer().then((buf) => sink(file.name, new Uint8Array(buf)))
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
  manifestInput.addEventListener('change', () => {
    const file = manifestInput.files?.[0]
    if (file) readFile(file, (_name, bytes) => handleManifestBytes(bytes))
    manifestInput.value = ''
  })
  bindingApply.addEventListener('click', applyDisclosure)
  loadSampleBtn.addEventListener('click', () => {
    void loadSampleBundle().catch(() => {
      results.replaceChildren(message(doc, 'Could not load the sample bundle from this deployment.'))
    })
  })

  return { handleBytes, handleManifestBytes, applyDisclosure, loadSampleBundle }
}

if (typeof document !== 'undefined' && document.getElementById('dropzone')) initApp(document)
