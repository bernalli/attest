import type { Disclosure } from 'attest-verifier'
import { intake, declinedForSize, trustStoreFromManifestBytes, type Refusal, type VerifyJob } from './intake.js'
import { BundleTooLargeError } from './bundle.js'
import { runVerify } from './run.js'
import {
  renderResult, renderRejection, renderDeclined, renderVerifyFailure,
  renderTamper, renderExhibit, renderExhibitTally, renderProbe,
} from './render.js'
import { LOG_KEYS, ANCHOR_POLICY } from './trusted-log.js'
import { b64uDecode } from './b64u.js'
import { loadSample } from './sample.js'
import { applyTamper, tamperOptions, type TamperId } from './tamper.js'
import { runExhibits } from './exhibits.js'
import { probeIsolation, browserProbeDeps, PROBE_URL, type ProbeDeps } from './probe.js'

export interface AppHandle {
  handleBytes(fileName: string, bytes: Uint8Array): void
  handleManifestBytes(bytes: Uint8Array): void
  applyDisclosure(): void
  loadSampleBundle(): Promise<void>
  applyTamperById(id: TamperId): void
  restore(): void
  showExhibits(): void
  runProbe(deps?: ProbeDeps): Promise<void>
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
  const bench = byId<HTMLElement>('bench')
  const benchButtons = byId<HTMLElement>('bench-buttons')
  const benchState = byId<HTMLElement>('bench-state')
  const benchRestore = byId<HTMLButtonElement>('bench-restore')
  const runExhibitsBtn = byId<HTMLButtonElement>('run-exhibits')
  const exhibitsZone = byId<HTMLElement>('exhibits')
  const runProbeBtn = byId<HTMLButtonElement>('run-probe')
  const probeZone = byId<HTMLElement>('probe')

  // `baseJobs` is what the file actually says; `currentJobs` is what is on
  // screen, which the bench may have altered. Keeping the two apart is what
  // makes "Put it back" honest — restoring re-renders the original bytes
  // rather than un-applying an edit, so no sequence of clicks can leave the
  // page showing a receipt that is neither the original nor the tampered one.
  let baseJobs: VerifyJob[] = []
  let currentJobs: VerifyJob[] = []
  let currentNotices: string[] = []
  let currentDisclosure: Disclosure | null = null
  let pendingEnvelope: { bytes: Uint8Array; label: string } | null = null

  // Notices are prepended on every render, not written once: `renderJobs` runs
  // again on every disclosure and on the manifest handover, and a warning that
  // disappears the moment the reader interacts with the page is a warning that
  // was never really there.
  // Two channels that must never be confused. `transparency` is EVIDENCE and
  // comes out of the dropped file — the §10.2 bundle a `proofs/` member held.
  // `logKeys` and `anchorPolicy` are this verifier's own pinned
  // CONFIGURATION, compiled into the page and never read off the material
  // being checked (v0.2 §7.3). Both are needed: supplying evidence with no
  // pinned log is not a check, and pinning a log with no evidence has nothing
  // to check. `witnessPolicy` stays absent, and that is a statement rather
  // than an omission — no independent witness co-signs this log's
  // checkpoints, so `corroboration` must never be able to reach `witnessed`.
  function renderJobs(disclosure: Disclosure | null): void {
    results.replaceChildren(
      ...currentNotices.map((text) => message(doc, text)),
      // Per job, never per batch: verify()'s trusted-config validation throws
      // by design, and an exception escaping this map would abandon the whole
      // `replaceChildren` call — leaving the page silently showing the
      // PREVIOUS results, which is the worst outcome available. One receipt
      // the page cannot check must not take the others down with it.
      ...currentJobs.map((job) => {
        try {
          return renderResult(
            job.label,
            runVerify(job.envelopeBytes, job.trustStore, null, disclosure, {
              transparency: job.transparency,
              logKeys: LOG_KEYS,
              anchorPolicy: ANCHOR_POLICY,
            }),
          )
        } catch (e) {
          return renderVerifyFailure(job.label, e instanceof Error ? e.message : String(e))
        }
      }),
    )
  }

  // The bench offers only what THIS receipt can actually have done to it, so
  // a button is never a promise the page then has to break.
  function refreshBench(): void {
    benchState.replaceChildren()
    benchRestore.hidden = true
    const base = baseJobs[0]
    const options = base ? tamperOptions(base.envelopeBytes) : []
    benchButtons.replaceChildren(
      ...options.map((option) => {
        const button = doc.createElement('button')
        button.type = 'button'
        button.textContent = option.label
        button.title = option.what
        button.dataset.tamper = option.id
        button.addEventListener('click', () => applyTamperById(option.id))
        return button
      }),
    )
    bench.hidden = options.length === 0
  }

  function setJobs(jobs: VerifyJob[]): void {
    baseJobs = jobs
    currentJobs = jobs
    currentDisclosure = null
    refreshBench()
    renderJobs(null)
  }

  function clearJobs(): void {
    baseJobs = []
    currentJobs = []
    refreshBench()
  }

  /** One refusal, one register. A container the page DECLINED to read gets the
   * neutral one; everything else gets the rejection. Both the reader below and
   * the admission boundary at the drop target arrive here, so the register can
   * never depend on which of them refused. */
  function showRefusal(r: Refusal): void {
    clearJobs()
    currentNotices = []
    // A receipt waiting for its key manifest is state about a file that is no
    // longer on screen, and hiding the manifest zone does not retract it: a
    // handover that arrives afterwards would find the wait still standing and
    // replace this refusal with a verdict about the PREVIOUS file. The offline
    // verifier already drops it here; this one did not.
    pendingEnvelope = null
    manifestZone.hidden = true
    results.replaceChildren(
      r.declined === true ? renderDeclined(r.reason) : renderRejection(r.reason),
    )
  }

  function handleBytes(fileName: string, bytes: Uint8Array): void {
    const r = intake(fileName, bytes)
    if (r.kind === 'rejected') {
      showRefusal(r)
      return
    }
    currentNotices = r.notices ?? []
    if (r.kind === 'needs-manifest') {
      clearJobs()
      pendingEnvelope = { bytes: r.envelopeBytes, label: r.label }
      manifestZone.hidden = false
      results.replaceChildren(
        ...currentNotices.map((text) => message(doc, text)),
        message(doc, 'This receipt has no issuer manifest embedded. Drop the issuer’s key-manifest JSON below (or verify a full .attest bundle instead, which carries it).'),
      )
      return
    }
    pendingEnvelope = null
    manifestZone.hidden = true
    setJobs(r.jobs)
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
    const envelope = pendingEnvelope
    pendingEnvelope = null
    manifestZone.hidden = true
    setJobs([{ label: envelope.label, envelopeBytes: envelope.bytes, trustStore, transparency: null }])
  }

  function applyDisclosure(): void {
    if (currentJobs.length === 0) return
    let salt: Uint8Array
    try {
      salt = b64uDecode(bindingSalt.value.trim())
    } catch {
      // The verdict stays on screen. Wiping it would leave the bench
      // narrating an edit whose consequence is nowhere to be seen — and the
      // bench's own header promises that the verdict below is what moves.
      renderJobs(currentDisclosure)
      results.prepend(
        message(doc, 'That salt is not valid base64url (unpadded). Copy it exactly from your .private.attest sidecar.'),
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

  // The bench alters the FIRST receipt only. A bundle may carry several, and
  // silently editing all of them would make the offset shown below true of
  // one file and false of the rest.
  function applyTamperById(id: TamperId): void {
    const base = baseJobs[0]
    if (!base) return
    const tampered = applyTamper(id, base.envelopeBytes, base.trustStore)
    if (!tampered) {
      // Back to the original too: leaving a PREVIOUS tamper on screen under
      // the words "nothing was altered" is the one reading this must not have.
      currentJobs = baseJobs
      benchRestore.hidden = true
      benchState.replaceChildren(
        message(doc, 'This receipt has nothing this button could change — nothing was altered.'),
      )
      renderJobs(currentDisclosure)
      return
    }
    // The transparency evidence is deliberately carried over UNCHANGED. It was
    // issued for the original bytes, so a tampered receipt makes the log proof
    // stop matching too, and the reader sees that happen on the same screen.
    currentJobs = [
      { ...base, envelopeBytes: tampered.envelopeBytes, trustStore: tampered.trustStore },
      ...baseJobs.slice(1),
    ]
    benchState.replaceChildren(renderTamper(tampered))
    benchRestore.hidden = false
    renderJobs(currentDisclosure)
  }

  function restore(): void {
    currentJobs = baseJobs
    benchState.replaceChildren()
    benchRestore.hidden = true
    renderJobs(currentDisclosure)
  }

  function showExhibits(): void {
    const outcomes = runExhibits()
    exhibitsZone.replaceChildren(renderExhibitTally(outcomes), ...outcomes.map(renderExhibit))
  }

  async function runProbe(deps: ProbeDeps = browserProbeDeps(doc)): Promise<void> {
    probeZone.replaceChildren(message(doc, 'Trying…'))
    const outcome = await probeIsolation(PROBE_URL, deps)
    probeZone.replaceChildren(renderProbe(outcome))
  }

  async function loadSampleBundle(): Promise<void> {
    const sample = await loadSample()
    bindingIdentifier.value = sample.binding.identifier
    bindingType.value = sample.binding.identifier_type
    bindingSalt.value = sample.binding.salt_b64u
    handleBytes('demo.attest', sample.bytes)
  }

  const readFile = (file: File, sink: (name: string, bytes: Uint8Array) => void): void => {
    // The size is metadata: asking for it reads no byte of the file, so a
    // container over §14.4's floor is refused here — before `arrayBuffer()`
    // brings a copy of it into this tab. Refusing after the copy would spend
    // exactly what the floor exists to protect and then report a limit.
    const refusal = declinedForSize(file.size)
    if (refusal !== null) {
      showRefusal(refusal)
      return
    }
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
  benchRestore.addEventListener('click', restore)
  loadSampleBtn.addEventListener('click', () => {
    void loadSampleBundle().catch((error: unknown) => {
      // A sample over the floor is not a deployment that lost its assets: it
      // is a container this page declined to read, and it earns §14.4's
      // neutral register like any other.
      if (error instanceof BundleTooLargeError) {
        showRefusal({ kind: 'rejected', reason: error.message, declined: true })
        return
      }
      clearJobs()
      results.replaceChildren(message(doc, 'Could not load the sample bundle from this deployment.'))
    })
  })
  // Replaying two receipts against a pinned log takes long enough to be felt,
  // and it is synchronous: without yielding first the button would appear
  // dead until the whole thing was over.
  runExhibitsBtn.addEventListener('click', () => {
    exhibitsZone.replaceChildren(message(doc, 'Replaying…'))
    setTimeout(showExhibits, 0)
  })
  runProbeBtn.addEventListener('click', () => {
    void runProbe()
  })

  // The bench's starting state is decided here, not by the `hidden` attribute
  // in the markup. Reading it off the page would make every assertion about
  // "the bench is closed until a receipt is checked" a statement about
  // index.html rather than about this file — true whatever this file did.
  refreshBench()

  return {
    handleBytes, handleManifestBytes, applyDisclosure, loadSampleBundle,
    applyTamperById, restore, showExhibits, runProbe,
  }
}

if (typeof document !== 'undefined' && document.getElementById('dropzone')) initApp(document)
