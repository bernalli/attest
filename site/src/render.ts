import type { VerifyRun } from './run.js'
import { COMPONENTS, explain, explainVerdict } from './explain.js'

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

  const dl = el('dl', 'components')
  for (const component of COMPONENTS) {
    const value = run.result[component]
    const e = explain(component, value)
    const row = el('div', `component tone-${e.tone}`)
    const dt = el('dt')
    dt.appendChild(el('span', 'component-name', e.label))
    dt.appendChild(el('code', 'component-value', value))
    row.appendChild(dt)
    row.appendChild(el('dd', undefined, e.text))
    dl.appendChild(row)
  }
  article.appendChild(dl)

  const warnings = list('Warnings', 'warnings', run.result.warnings)
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
