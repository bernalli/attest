import type { VerifyRun } from './run.js'
import type { Component } from './explain.js'
import { GROUPS, attributeWarning, displayValue, explain, explainVerdict } from './explain.js'
import { segmentDiagnostic } from './diagnostic.js'
import { neutralized } from './untrusted-text.js'

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
