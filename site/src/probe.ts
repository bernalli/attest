// The page says it cannot talk to any other host. Rather than repeat that in
// prose, it tries — and shows what the browser answered.
//
// The claim being demonstrated is exactly this one: the receipt you dropped
// cannot leave this tab, because the page's own Content-Security-Policy
// forbids every connection that is not same-origin. So the probe attempts a
// request to a host that is not this one and reports the outcome verbatim:
// the policy violation the browser itself recorded when there is one, the
// thrown error otherwise.
//
// The branch that matters is the one nobody wants: if the request GOES
// THROUGH, the probe says so. A page that reports a block it did not observe
// would be worse than a page that made no claim at all — it would be a
// fabricated demonstration, which is the exact failure this section exists to
// rule out.

/** A host under a reserved TLD (RFC 2606): never registrable, never resolvable. */
export const PROBE_URL = 'https://store.nebula.example/.well-known/attest/keys.json'

export interface ProbeOutcome {
  url: string
  blocked: boolean
  /** True only when the BROWSER recorded a policy violation for this request.
   *  The probe URL is under a reserved TLD and never resolves, so a bare
   *  rejection is what an ordinary DNS failure looks like too — it is not
   *  evidence of confinement, and must not be shown as if it were. */
  observed: boolean
  /** The browser's own words — a policy report, or the error it threw. */
  detail: string
}

export interface ProbeDeps {
  fetch: (url: string) => Promise<unknown>
  /** Subscribes to policy violations; returns the unsubscribe. */
  onViolation: (cb: (event: SecurityPolicyViolationEvent) => void) => () => void
  /** Yields long enough for a violation dispatched as its own task to land. */
  settle?: () => Promise<void>
}

// Browsers reject the request and dispatch `securitypolicyviolation`
// independently, and Chromium reaches the rejection first: reading the
// violation the instant the promise settles finds nothing, and the probe
// falls back to reporting a bare "TypeError: Failed to fetch" — which is what
// an ordinary network failure looks like too, and therefore demonstrates
// nothing. One macrotask is enough for the event to arrive, and it is only
// ever waited for when no violation has been seen yet.
const oneTask = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0))

export const browserProbeDeps = (doc: Document): ProbeDeps => ({
  fetch: (url) => globalThis.fetch(url, { mode: 'cors' }),
  onViolation: (cb) => {
    const handler = (event: Event): void => cb(event as SecurityPolicyViolationEvent)
    doc.addEventListener('securitypolicyviolation', handler)
    return () => doc.removeEventListener('securitypolicyviolation', handler)
  },
})

const describeViolation = (event: SecurityPolicyViolationEvent): string =>
  `The browser refused the request and recorded the violation itself: ` +
  `blocked-uri ${event.blockedURI}, violated-directive ${event.violatedDirective}.`

export async function probeIsolation(url: string, deps: ProbeDeps): Promise<ProbeOutcome> {
  let violation: SecurityPolicyViolationEvent | null = null
  // Only THIS request's violation counts. The page can be recording others at
  // the same moment — a blocked font, an extension's injected resource — and
  // adopting one of those would print a report about somebody else's request
  // under a sentence that says "the browser refused the request".
  const origin = new URL(url).origin
  const off = deps.onViolation((event) => {
    const blocked = event.blockedURI ?? ''
    if (violation === null && (blocked === url || blocked === origin)) violation = event
  })
  try {
    await deps.fetch(url)
  } catch (e) {
    const reason = e instanceof Error ? `${e.name}: ${e.message}` : String(e)
    // Still subscribed here: `off()` runs in the finally, after this returns.
    if (violation === null) await (deps.settle ?? oneTask)()
    return {
      url,
      blocked: true,
      observed: violation !== null,
      detail: violation
        ? describeViolation(violation)
        : `The request failed before it could carry anything anywhere — ${reason}. ` +
          'The browser recorded no policy violation, so this run does not by itself ' +
          'show the policy did it: an unreachable host fails the same way.',
    }
  } finally {
    off()
  }
  // Honest failure branch: this deployment did not confine the page, and
  // saying otherwise here would fabricate the very thing being demonstrated.
  return {
    url,
    blocked: false,
    observed: false,
    detail:
      'The request was NOT blocked: it reached the network. This page is not confined the way ' +
      'it says it is — treat every claim about isolation on this deployment as unproven, and ' +
      'verify your receipt with the command-line tool instead.',
  }
}
