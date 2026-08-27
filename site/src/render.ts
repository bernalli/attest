import type { VerifyRun } from './run.js'
import type { Component } from './explain.js'
import { GROUPS, attributeWarning, explain, explainVerdict } from './explain.js'

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

function list(title: string, className: string, items: string[]): HTMLElement | null {
  if (items.length === 0) return null
  const wrap = el('div', className)
  wrap.appendChild(el('h4', undefined, title))
  const ul = el('ul')
  for (const item of items) ul.appendChild(el('li', undefined, item))
  wrap.appendChild(ul)
  return wrap
}

// Split `warnings[]` into the rows they qualify and the ones that qualify the
// receipt as a whole. Attribution never drops a warning: whatever no rule
// claims keeps its old place in the flat list below the rows.
function bucketWarnings(warnings: string[]): {
  byComponent: Map<Component, string[]>
  unattributed: string[]
} {
  const byComponent = new Map<Component, string[]>()
  const unattributed: string[] = []
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

function componentRow(component: Component, run: VerifyRun, warnings: string[]): HTMLElement {
  const value = run.result[component]
  const e = explain(component, value, run.result)
  const row = el('div', `component tone-${e.tone}`)
  const dt = el('dt')
  dt.appendChild(el('span', 'component-name', e.label))
  dt.appendChild(el('code', 'component-value', value))
  row.appendChild(dt)
  row.appendChild(el('dd', undefined, e.text))
  if (warnings.length > 0) {
    // The warning stays VERBATIM: these tokens are a cross-language wire
    // surface a reader can search for, and paraphrasing one here would send
    // them looking for words the spec does not use.
    const dd = el('dd', 'component-warnings')
    const ul = el('ul')
    for (const w of warnings) ul.appendChild(el('li', undefined, w))
    dd.appendChild(ul)
    row.appendChild(dd)
  }
  return row
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
  const { byComponent, unattributed } = bucketWarnings(run.result.warnings)
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
  const errors = list('Errors', 'errors', run.result.errors)
  if (errors) article.appendChild(errors)

  const details = el('details')
  details.appendChild(el('summary', undefined, 'Raw result'))
  details.appendChild(el('pre', 'raw', JSON.stringify(run.result, null, 2)))
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
