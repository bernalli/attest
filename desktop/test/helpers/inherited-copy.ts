import ts from 'typescript'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

/**
 * The mechanical half of the inherited-copy audit (plan step 5b).
 *
 * The artifact freezes every string it inlines: a sentence that is wrong when the file
 * is built stays wrong on every downloaded copy, for ever, to readers who have no way
 * to check it. So the copy this package INHERITS — it imports the catalogue whole and
 * renders all of it — is enumerated here rather than read by eye, and the enumeration
 * is re-run by the suite so that a sentence added upstream after the audit fails a test
 * instead of arriving unseen.
 */

/** The modules the artifact inlines from `site/src`. Closed list: it is exactly the
 *  read-only import surface the plan's §3.1 enumerates, and `styles.css` carries no
 *  text (no `content:` rule), so it contributes no string. */
export const INHERITED_MODULES = [
  'b64u', 'bundle', 'explain', 'intake', 'render', 'run', 'trusted-log',
] as const

/** Closed token list of the audit's step (a). A sentence outside it is out of scope by
 *  construction rather than by judgement; widening the list is a plan edit, not a
 *  runtime choice. Order matters only for reporting: the first match is recorded. */
export const AUDIT_TOKENS = [
  'can fetch', 'can be', 'can ', 'CLI', 'will ', 'is able', 'supports', 'use the',
  'run ', 'available',
  // Appended LAST on purpose: the list is first-match, so a token added at the head
  // would silently re-label every audited row. Measured 2026-09-01: `fetch` widens the
  // catalogue from 17 candidates to 18, and the one it adds is the copy that describes
  // the `verified` tier — the same family as the sentence gate G1 was built for, which
  // the two-word phrase `can fetch` catches only in its historical wording.
  'fetch',
] as const

export interface CopySource {
  module: string
  text: string
}

export interface CopyCandidate {
  module: string
  /** The first token of AUDIT_TOKENS the string contains. */
  token: string
  /** The exact string literal, verbatim. */
  text: string
  /** SHA-256 of `text`, UTF-8, hex. The audit records this so that REWORDING an
   *  audited sentence upstream is caught as surely as adding a new one. */
  sha256: string
}

/** Every string literal in a TypeScript source, template literals included. A template
 *  with substitutions is joined with `…` where the holes are, which is how such a
 *  string reads to a person anyway. */
function stringLiterals(fileName: string, source: string): string[] {
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.ES2022, true)
  const out: string[] = []
  const walk = (node: ts.Node): void => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      out.push(node.text)
    } else if (ts.isTemplateExpression(node)) {
      out.push(node.head.text + node.templateSpans.map((s) => `…${s.literal.text}`).join(''))
      node.templateSpans.forEach((s) => walk(s.expression))
      return
    }
    ts.forEachChild(node, walk)
  }
  walk(file)
  return out
}

export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

/** The pure half: given sources, the candidates. Pure so that the guard can be pointed
 *  at a fixture and SEEN to catch a planted sentence, instead of being trusted. */
export function enumerateCandidates(sources: readonly CopySource[]): CopyCandidate[] {
  const out: CopyCandidate[] = []
  for (const source of sources) {
    for (const text of stringLiterals(`${source.module}.ts`, source.text)) {
      const token = AUDIT_TOKENS.find((t) => text.includes(t))
      if (token === undefined) continue
      out.push({ module: source.module, token, text, sha256: sha256Hex(text) })
    }
  }
  return out
}

/** The I/O half: the real catalogue, read from disk at test time. */
export function readInheritedSources(): CopySource[] {
  return INHERITED_MODULES.map((module) => ({
    module,
    text: readFileSync(
      fileURLToPath(new URL(`../../../site/src/${module}.ts`, import.meta.url)),
      'utf8',
    ),
  }))
}

export function enumerateInheritedCopy(): CopyCandidate[] {
  return enumerateCandidates(readInheritedSources())
}
