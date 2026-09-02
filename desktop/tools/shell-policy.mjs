// The markup rules for the single-file verifier, in one place.
//
// They are an ALLOWLIST over the HTML tokenizer's start-tag stream: every element name,
// every attribute, every value and every resolved URL must be one this file enumerates,
// wherever the tag occurs. Anything else is refused BY NAME, so a construct nobody
// thought of is refused for not being on the list rather than accepted for not being on
// a list of dangers.
//
// It reads TOKENS and not a tree on purpose. Tree builders disagree: parse5 still
// implements the pre-relaxation "in select" insertion mode and drops a <meta>, an <img>
// or an <a> written inside a <select>, while current engines keep them and act on them.
// A start-tag token, on the other hand, becomes an element in every tree builder there
// is, so the token stream is a superset of every tree and the check does not depend on
// how engines evolve tree construction.
//
// It reads RESOLVED urls and RAW bytes, never the spelling in between. The HTML parser
// decodes character references and normalises CR before the URL parser strips tabs,
// newlines and control characters and lowercases the scheme — so `java&Tab;script:` and
// `&#106;avascript:` are the same link to a browser and different strings to a regex.

import { Parser } from 'parse5'

/** Any `file:` base works: every relative reference is refused anyway, and pinning one
 *  keeps the resolved form of the artifact's own anchor stable across machines. */
export const BASE_URL = 'file:///attest-verifier.html'

/** Closed. Widening it is a deliberate edit with a test, never a runtime choice. */
export const ALLOWED_HOSTS = ['attest-receipts.org']

class ShellInputError extends Error {}

/** The document as bytes, refusing anything the browser would read differently from the
 *  validator. A byte order mark is the sharp case: parse5 keeps it, and with it in front
 *  the document parses in quirks mode with an EMPTY head, so every rule about what the
 *  head may hold would read nothing at all. */
export function decodeShell(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  if (view[0] === 0xef && view[1] === 0xbb && view[2] === 0xbf)
    throw new ShellInputError('byte order mark')
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(view)
  } catch {
    throw new ShellInputError('invalid UTF-8')
  }
}

/** Every start-tag token, in document order, before any tree builder can drop one.
 *  `scriptingEnabled: false` so the contents of <noscript> are tokenized too: that is
 *  more than any engine with scripting on will build, which is the direction this check
 *  wants to err in. */
export function tokenizeShell(html) {
  const tokens = []
  const endTags = []
  const parseErrors = []
  class RecordingParser extends Parser {
    onStartTag(token) {
      tokens.push({ name: token.tagName, attrs: token.attrs, location: token.location })
      super.onStartTag(token)
    }
    onEndTag(token) {
      endTags.push({ name: token.tagName, location: token.location })
      super.onEndTag(token)
    }
  }
  const parser = new RecordingParser({
    sourceCodeLocationInfo: true,
    scriptingEnabled: false,
    onParseError: (error) => parseErrors.push({ code: error.code, location: error }),
  })
  parser.tokenizer.write(html, true)
  return { tokens, endTags, parseErrors, document: parser.document, html }
}

/** The text a browser will execute or apply, taken from the tokenizer's own idea of
 *  where the element ends. The regex that computes the hashes cannot do this: a
 *  `<!--<script>` inside the module makes the tokenizer run past the first `</script>`
 *  and the regex stop at it. */
export function scriptAndStyleText(tokenized) {
  const textOf = (name) => {
    const start = tokenized.tokens.find((t) => t.name === name)
    if (start === undefined) return null
    const end = tokenized.endTags.find(
      (t) => t.name === name && t.location.startOffset >= start.location.endOffset,
    )
    if (end === undefined) return null
    return tokenized.html.slice(start.location.endOffset, end.location.startOffset)
  }
  return { script: textOf('script'), style: textOf('style') }
}

const refusal = (rule, where, detail) => ({ rule, where, detail })
const at = (token) => `${token.name}@${token.location.startOffset}`

export const RULE_IDS = ['R-INPUT', 'R-PARSE']

export const RULES = [
  {
    id: 'R-INPUT',
    // The decode happens before any rule runs: a document that could not be decoded has
    // no tokens to judge. The entry exists so the rule is nameable and countable.
    check: () => [],
  },
  {
    id: 'R-PARSE',
    check: (ctx) =>
      ctx.parseErrors.map((e) =>
        refusal('R-PARSE', `document@${e.location.startOffset}`, `${e.code}@${e.location.startOffset}`),
      ),
  },
]

/**
 * Every refusal the document earns, or an empty array. `rules` is a parameter so a test
 * can remove one rule and watch a mutant go from refused to accepted — the only proof
 * that a rule is load-bearing. Nothing but the tests ever passes it.
 */
export function validateShell(bytes, options, rules = RULES) {
  let html
  try {
    html = decodeShell(bytes)
  } catch (e) {
    return [refusal('R-INPUT', 'document@0', e instanceof Error ? e.message : String(e))]
  }
  const tokenized = tokenizeShell(html)
  const ctx = {
    ...tokenized,
    stage: options.stage,
    expectedCsp: options.expectedCsp,
  }
  return rules.flatMap((rule) => rule.check(ctx))
}
