import type { VerifyRun } from './run.js'
import type { Component } from './explain.js'
import { GROUPS, attributeWarning, displayValue, explain, explainVerdict } from './explain.js'
import { segmentDiagnostic } from './diagnostic.js'
import { neutralized } from './untrusted-text.js'
import type { Tampered } from './tamper.js'
import type { ExhibitRun } from './exhibits.js'
import type { ProbeOutcome } from './probe.js'

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== undefined) node.textContent = text
  return node
}

// C-86: a diagnostic is library-COMPOSED text over attacker-influenced
// operands — nothing signs a word of it, exactly as nothing signed a ZIP
// member name (C-70). So the page renders it as DATA: wire tokens and framings
// the page itself knows in the page's own voice, every operand inside a <q>
// citation, neutralized. A <q> is a boundary no character of the operand can
// close, unlike an in-band quote.
//
// On benign input the li's textContent stays byte-identical to the wire
// string, so a reader can still search for the words the spec uses; the
// verbatim string always survives in the Raw result JSON below, which is the
// declared quarantine and does not clip.
//
// The cap is anti-flooding, not anti-persuasion: a short hostile sentence sits
// entirely inside the citation, and it is the citation that disarms it.
const MAX_DIAG_OPERAND_CHARS = 300

function operandNode(text: string): HTMLQuoteElement {
  return el('q', 'diag-operand', neutralized(text, MAX_DIAG_OPERAND_CHARS))
}

// The same cap and the same character policy the fallback sentence applies to
// a value it cannot speak (explain.ts). A component value is untrusted text on
// the surface a reader sees: <code> keeps it out of the page's prose, and
// nothing else about the element makes a bidi override or a 50 000-character
// run harmless. Neutralizing here is byte-identical on every benign value, so
// a reader can still search for the word the spec uses.
const MAX_COMPONENT_VALUE_CHARS = 120

function diagnosticItem(diagnostic: unknown): HTMLLIElement {
  const li = el('li', 'diagnostic')
  const seg = segmentDiagnostic(diagnostic)
  if (seg.kind === 'token') {
    li.appendChild(el('code', 'diag-code', seg.code))
  } else if (seg.kind === 'known-literal') {
    li.textContent = seg.text
  } else if (seg.kind === 'composed') {
    for (const part of seg.parts) {
      if (part.kind === 'literal') li.appendChild(document.createTextNode(part.text))
      else li.appendChild(operandNode(part.text))
    }
  } else {
    li.appendChild(operandNode(seg.operand))
  }
  return li
}

function list(title: string, className: string, items: readonly unknown[]): HTMLElement | null {
  if (items.length === 0) return null
  const wrap = el('div', className)
  wrap.appendChild(el('h4', undefined, title))
  const ul = el('ul')
  for (const item of items) ul.appendChild(diagnosticItem(item))
  wrap.appendChild(ul)
  return wrap
}

// Split `warnings[]` into the rows they qualify and the ones that qualify the
// receipt as a whole. Attribution never drops a warning: whatever no rule
// claims keeps its old place in the flat list below the rows.
function bucketWarnings(warnings: readonly unknown[]): {
  byComponent: Map<Component, unknown[]>
  unattributed: unknown[]
} {
  const byComponent = new Map<Component, unknown[]>()
  const unattributed: unknown[] = []
  for (const warning of warnings) {
    const component = attributeWarning(warning)
    if (component === null) {
      unattributed.push(warning)
      continue
    }
    const bucket = byComponent.get(component)
    if (bucket) bucket.push(warning)
    else byComponent.set(component, [warning])
  }
  return { byComponent, unattributed }
}

function componentRow(component: Component, run: VerifyRun, warnings: readonly unknown[]): HTMLElement {
  const value: unknown = run.result[component]
  const e = explain(component, value, run.result)
  const row = el('div', `component tone-${e.tone}`)
  const dt = el('dt')
  dt.appendChild(el('span', 'component-name', e.label))
  dt.appendChild(
    el('code', 'component-value', neutralized(displayValue(value), MAX_COMPONENT_VALUE_CHARS)),
  )
  row.appendChild(dt)
  row.appendChild(el('dd', undefined, e.text))
  if (warnings.length > 0) {
    // Nothing here is paraphrased: these tokens are a cross-language wire
    // surface a reader can search for, and rewording one would send them
    // looking for words the spec does not use. But the string is not the
    // page's prose either — see diagnosticItem above for the split.
    const dd = el('dd', 'component-warnings')
    const ul = el('ul')
    for (const w of warnings) ul.appendChild(diagnosticItem(w))
    dd.appendChild(ul)
    row.appendChild(dd)
  }
  return row
}

// The declared quarantine must not be the thing that takes the card down:
// `JSON.stringify` throws on a bigint and on a cycle, and neither is excluded
// by a type that describes a well-formed result.
function rawJson(result: unknown): string {
  try {
    return JSON.stringify(result, (_k, v: unknown) => (typeof v === 'bigint' ? `${v}` : v), 2)
  } catch {
    return '(this result cannot be shown as JSON — see the rows above)'
  }
}

export function renderResult(label: string, run: VerifyRun): HTMLElement {
  const article = el('article', 'result')
  const verdict = explainVerdict(run.ok)

  const header = el('header')
  header.appendChild(el('h3', undefined, label))
  const badge = el('p', `verdict tone-${verdict.tone}`)
  badge.appendChild(el('strong', undefined, verdict.label))
  badge.appendChild(el('span', undefined, ` ${verdict.text}`))
  header.appendChild(badge)
  article.appendChild(header)

  // Ten rows under three questions rather than one flat run of ten. The
  // grouping is the copy decision of V-G.2 D5, and it is what stops the five
  // components v0.2 added from being read as footnotes to the five v0.1 had.
  // Two array fields the contract names and a dropped file may not supply.
  // `for...of` on `undefined` throws, and a throw here abandons the card.
  const resultWarnings: readonly unknown[] = Array.isArray(run.result.warnings)
    ? run.result.warnings
    : []
  const resultErrors: readonly unknown[] = Array.isArray(run.result.errors) ? run.result.errors : []
  const { byComponent, unattributed } = bucketWarnings(resultWarnings)
  for (const group of GROUPS) {
    const section = el('section', 'group')
    section.appendChild(el('h4', 'group-question', group.question))
    section.appendChild(el('p', 'group-note', group.note))
    const dl = el('dl', 'components')
    for (const component of group.components) {
      dl.appendChild(componentRow(component, run, byComponent.get(component) ?? []))
    }
    section.appendChild(dl)
    article.appendChild(section)
  }

  // "Other" only when some warnings did land on a row: otherwise this list is
  // still the whole set and must not imply there is more of it elsewhere.
  const flatTitle = byComponent.size > 0 ? 'Other warnings' : 'Warnings'
  const warnings = list(flatTitle, 'warnings', unattributed)
  if (warnings) article.appendChild(warnings)
  const errors = list('Errors', 'errors', resultErrors)
  if (errors) article.appendChild(errors)

  const details = el('details')
  details.appendChild(el('summary', undefined, 'Raw result'))
  details.appendChild(el('pre', 'raw', rawJson(run.result)))
  article.appendChild(details)

  return article
}

// The verifier itself could not run for this receipt — a fault in this page's
// own configuration, not a judgement on the file. verify()'s trusted-config
// checks throw by design (a configuration bug must never be swallowed), so
// something has to catch them where a reader can see it. Two rules hold this
// text together: it says nothing about the receipt's validity, in either
// direction, and it shows the reason instead of burying it in the console,
// because a fault nobody can see is a fault nobody reports.
export function renderVerifyFailure(label: string, reason: string): HTMLElement {
  const article = el('article', 'result unverifiable')
  const header = el('header')
  header.appendChild(el('h3', undefined, label))
  article.appendChild(header)
  article.appendChild(
    el(
      'p',
      'verdict tone-neutral',
      'This page could not check this receipt — the fault is in the verifier’s own ' +
        'configuration, not in your file. Nothing here says whether the receipt is ' +
        'genuine: it was never examined. Try the attest CLI, or a copy of this page ' +
        'from another source.',
    ),
  )
  article.appendChild(el('p', 'unverifiable-reason', reason))
  return article
}

export function renderRejection(reason: string): HTMLElement {
  const article = el('article', 'result rejected')
  article.appendChild(el('p', 'verdict tone-bad', reason))
  return article
}

// --------------------------------------------------------------------------
// The demonstration surfaces. Each one exists to move a sentence off the page
// and into something the reader watches happen.
// --------------------------------------------------------------------------

// The title of the thing that was bought, and the seller's display name, are
// strings out of a dropped file — untrusted on exactly the footing a
// diagnostic operand is (C-86), and printed here inside the page's own
// sentence about what the bench just did. The cap matches the component value
// beside a row, because this is the same kind of thing shown the same way.
const MAX_TAMPER_VALUE_CHARS = 120

/** What the bench just did to the receipt, in terms a reader can check. */
export function renderTamper(tampered: Tampered): HTMLElement {
  const box = el('div', 'tamper-state')
  box.appendChild(el('h4', undefined, tampered.option.label))
  const edit = tampered.edit
  if (edit === null) {
    // Nothing was touched, and saying "one byte changed" here would be a
    // small lie in the one place on the page that must not tell any.
    box.appendChild(el('p', undefined, `${tampered.option.what} Nothing in the file changed.`))
    return box
  }
  // `path` is this page's own literal, and `before`/`after` are one ASCII
  // letter or digit each by construction in tamper.ts — the byte it turns is
  // chosen from that class precisely so the demonstration stays about
  // signatures. Only the two whole values come from the file.
  const p = el('p')
  p.appendChild(document.createTextNode('Changed one byte at offset '))
  p.appendChild(el('code', undefined, String(edit.offset)))
  p.appendChild(document.createTextNode(' of the receipt — inside '))
  p.appendChild(el('code', undefined, edit.path))
  p.appendChild(document.createTextNode(': '))
  p.appendChild(el('code', undefined, edit.before))
  p.appendChild(document.createTextNode(' became '))
  p.appendChild(el('code', undefined, edit.after))
  p.appendChild(document.createTextNode('.'))
  box.appendChild(p)
  const values = el('p', 'tamper-values')
  values.appendChild(el('code', 'tamper-value was', neutralized(edit.was, MAX_TAMPER_VALUE_CHARS)))
  values.appendChild(document.createTextNode(' → '))
  values.appendChild(el('code', 'tamper-value now', neutralized(edit.now, MAX_TAMPER_VALUE_CHARS)))
  box.appendChild(values)
  return box
}

/** One §19 exhibit: its story, its verdict, and the fixture it is held to. */
export function renderExhibit(outcome: ExhibitRun): HTMLElement {
  const section = el('section', `exhibit${outcome.matches ? '' : ' mismatch'}`)
  section.appendChild(el('h3', undefined, outcome.exhibit.label))
  section.appendChild(el('p', 'exhibit-story', outcome.exhibit.story))

  // Provenance before verdict: an exhibit whose source a reader cannot go and
  // read is an assertion with extra steps.
  const source = el('p', 'exhibit-source')
  source.appendChild(document.createTextNode('Conformance vector '))
  source.appendChild(el('code', undefined, outcome.exhibit.id))
  source.appendChild(document.createTextNode(', replayed in this tab just now.'))
  section.appendChild(source)

  section.appendChild(renderResult(outcome.exhibit.label, outcome.run))

  const check = el('p', `exhibit-check tone-${outcome.matches ? 'good' : 'bad'}`)
  check.textContent = outcome.matches
    ? 'This result matches the vector’s expected.json field for field — the page is being held ' +
      'to the corpus, not asking to be believed.'
    : 'This result does NOT match the vector’s expected.json. Something here is wrong, and the ' +
      'page is saying so rather than hiding it:'
  section.appendChild(check)
  const mismatches = list('Mismatches', 'errors', outcome.mismatches)
  if (mismatches) section.appendChild(mismatches)
  return section
}

/** The tally, counted from the runs — never a number written by hand. */
export function renderExhibitTally(outcomes: ExhibitRun[]): HTMLElement {
  const matched = outcomes.filter((o) => o.matches).length
  const good = matched === outcomes.length
  const p = el('p', `exhibit-tally tone-${good ? 'good' : 'bad'}`)
  p.textContent =
    `${outcomes.length} conformance vectors replayed in your browser; ` +
    `${matched} produced exactly the result the corpus demands` +
    (good ? '.' : ` — ${outcomes.length - matched} did not, and that is a defect in this page.`)
  return p
}

// The detail is the browser's own words — a policy report it composed, or the
// message it put on the error it threw. Neither is the page's prose, and both
// are byte-identical through the neutralizer on anything a browser actually
// produces; running them through it costs nothing and stops this surface from
// being the one place a composed string reaches the reader unexamined.
const MAX_PROBE_DETAIL_CHARS = 400

/** Whether this page could reach another host, as the browser reported it. */
export function renderProbe(outcome: ProbeOutcome): HTMLElement {
  // Three states, not two. "good" is reserved for the one the browser itself
  // witnessed; a bare rejection is "neutral", because this URL is under a
  // reserved TLD that never resolves and would fail identically on a page
  // with no policy at all. Painting that green would assert exactly the
  // confinement the fallback branch failed to observe.
  const tone = outcome.blocked ? (outcome.observed ? 'good' : 'neutral') : 'bad'
  const box = el('div', `probe tone-${tone}`)
  const p = el('p')
  p.appendChild(document.createTextNode(outcome.blocked ? 'Tried to reach ' : 'Reached '))
  p.appendChild(el('code', undefined, outcome.url))
  p.appendChild(
    document.createTextNode(
      outcome.blocked
        ? outcome.observed
          ? ' — and the browser refused it under this page’s own policy.'
          : ' — and could not. Why, this run cannot say.'
        : '.',
    ),
  )
  box.appendChild(p)
  box.appendChild(
    el('p', 'probe-detail', neutralized(outcome.detail, MAX_PROBE_DETAIL_CHARS)),
  )
  return box
}
