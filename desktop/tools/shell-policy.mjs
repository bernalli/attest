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
      // The attributes are COPIED, not referenced. The tree builder adjusts foreign
      // content in place after this returns — it renames `xlink:href` to `href` on its
      // way into the SVG namespace — so a recorded reference would hand the rules the
      // name the tree ended up with instead of the one the document spells.
      tokens.push({
        name: token.tagName,
        attrs: token.attrs.map((attr) => ({ name: attr.name, value: attr.value })),
        location: token.location,
      })
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

/** Allowed on every element the list below names, because none of them can carry a URL
 *  or make the browser fetch anything. */
const GLOBAL_ATTRIBUTES = ['id', 'class', 'hidden', 'role', 'tabindex', 'lang']
const isGlobal = (name) => GLOBAL_ATTRIBUTES.includes(name) || name.startsWith('aria-')

/** The inventory of the shell, turned into a list. Everything else — img, link, base,
 *  iframe, object, embed, form, video, audio, source, track, svg, math, template,
 *  noscript, custom elements — is refused for not being here, so a construct nobody
 *  thought of does not need a rule of its own. */
const ELEMENTS = {
  html: [], head: [], body: [], title: [], header: [], h1: [], main: [], section: [],
  div: [], strong: [], span: [], p: [], details: [], summary: [], footer: [], em: [],
  code: [], select: [],
  meta: ['charset', 'name', 'content', 'http-equiv'],
  input: ['type'],
  button: ['type'],
  label: ['for'],
  option: ['value'],
  a: ['href'],
  script: ['type'],
  style: [],
}

const allowedElement = (name, stage) =>
  Object.hasOwn(ELEMENTS, name) && !(stage === 'source' && name === 'style')

/** Attributes refused wherever they appear, on an allowlisted element or not: every
 *  event handler, every namespaced name (xlink:href, xml:base), and the four that turn
 *  an inert element into something that styles, slots or shadows. */
const alwaysRefused = (name) =>
  name.startsWith('on') ||
  name.includes(':') ||
  name === 'style' ||
  name === 'is' ||
  name === 'slot' ||
  name === 'shadowrootmode'

const attributesOf = (token) => {
  const map = new Map()
  for (const attr of token.attrs) if (!map.has(attr.name)) map.set(attr.name, attr.value)
  return map
}

/** Whether an allowlisted element may carry this attribute. The stylesheet may carry
 *  none at all, not even a global one: `<style media>` is a stylesheet that applies
 *  conditionally, which this document has no use for. */
const mayCarry = (element, attribute, stage) => {
  if (element === 'style') return false
  if (isGlobal(attribute)) return true
  if (element === 'script' && stage === 'source' && attribute === 'src') return true
  return (ELEMENTS[element] ?? []).includes(attribute)
}

const META_SHAPES = [
  { id: 'charset', keys: ['charset'], values: { charset: (v) => v.toLowerCase() === 'utf-8' } },
  {
    id: 'viewport',
    keys: ['content', 'name'],
    values: {
      name: (v) => v.toLowerCase() === 'viewport',
      content: (v) => v === 'width=device-width, initial-scale=1',
    },
  },
  {
    id: 'policy',
    keys: ['content', 'http-equiv'],
    artifactOnly: true,
    values: {
      'http-equiv': (v) => v.toLowerCase() === 'content-security-policy',
      content: (v, ctx) => v === ctx.expectedCsp,
    },
  },
]

/** Which of the three shapes a meta token is, or null. The key set must match exactly:
 *  a meta with one attribute more is a meta this document has no use for. */
const metaShape = (token, ctx) => {
  const attrs = attributesOf(token)
  const keys = [...attrs.keys()].sort()
  for (const shape of META_SHAPES) {
    if (shape.artifactOnly === true && ctx.stage !== 'artifact') continue
    if (keys.length !== shape.keys.length) continue
    if (!shape.keys.every((k, i) => k === keys[i])) continue
    if (shape.keys.every((k) => shape.values[k](attrs.get(k), ctx))) return shape.id
  }
  return null
}

/** The canonical spelling of the one link this document may carry: the attribute name in
 *  any case the parser accepts, then `="` + the URL exactly as the WHATWG parser
 *  serialises it + `"`. Comparing the SOURCE BYTES and not the decoded value is the
 *  whole point: the parser decodes `&#104;ttps:` and `https&colon;` into the allowed
 *  link, so a rule that read the decoded value would accept every spelling of it. */
const canonicalRaw = (raw, expected) =>
  raw.slice(0, 4).toLowerCase() === 'href' && raw.slice(4) === `="${expected}"`

/**
 * What a browser would do with this href, and whether the document may carry it. The
 * verdict is on the RESOLVED url — after character references are decoded, tabs and
 * newlines dropped and the scheme lowercased — and on the raw bytes, never on the
 * spelling in between.
 */
export function classifyUrl(raw, value, ids) {
  let url
  try {
    url = new URL(value, BASE_URL)
  } catch {
    return {
      raw, value, resolved: null, protocol: null, host: null,
      accepted: false, reason: 'unparseable',
    }
  }
  const verdict = (accepted, reason) => ({
    raw, value, resolved: url.href, protocol: url.protocol, host: url.host, accepted, reason,
  })
  if (url.protocol === 'https:' && ALLOWED_HOSTS.includes(url.host)) {
    // A username in front of an allowed host is a link that READS as somewhere else.
    if (url.username !== '' || url.password !== '') return verdict(false, 'userinfo')
    return canonicalRaw(raw, url.href) ? verdict(true, '') : verdict(false, 'canonical')
  }
  if (value.startsWith('#') && value.length > 1) {
    if (!ids.has(value.slice(1))) return verdict(false, 'missing-target')
    return canonicalRaw(raw, value) && url.href === `${BASE_URL}${value}`
      ? verdict(true, '')
      : verdict(false, 'canonical')
  }
  return verdict(false, 'scheme')
}

const idsOf = (ctx) => {
  const ids = new Set()
  for (const token of ctx.tokens)
    for (const attr of token.attrs) if (attr.name === 'id') ids.add(attr.value)
  return ids
}

/** Every anchor's href, with the source bytes of the attribute beside the decoded value. */
const anchors = (ctx) => {
  const ids = idsOf(ctx)
  return ctx.tokens
    .filter((t) => t.name === 'a')
    .flatMap((token) => {
      const href = attributesOf(token).get('href')
      if (href === undefined) return []
      const span = token.location.attrs?.href
      const raw =
        span === undefined ? '' : ctx.html.slice(span.startOffset, span.endOffset)
      return [{ token, verdict: classifyUrl(raw, href, ids) }]
    })
}

const urlRule = (id, reasons) => ({
  id,
  check: (ctx) =>
    anchors(ctx)
      .filter(({ verdict }) => !verdict.accepted && reasons.includes(verdict.reason))
      .map(({ token, verdict }) =>
        refusal(
          id,
          at(token),
          `${verdict.reason}: ${verdict.raw.slice(0, 60)} resolves to ` +
            `${verdict.resolved === null ? 'nothing a URL parser can read' : verdict.resolved}`,
        ),
      ),
})

const first = (ctx, name) => ctx.tokens.find((t) => t.name === name)

export const RULE_IDS = ['R-INPUT', 'R-PARSE', 'R-ELEMENT', 'R-ATTRIBUTE', 'R-VALUE', 'R-META',
                         'R-COUNT', 'R-URL', 'R-URL-CANONICAL', 'R-REF']

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
  {
    id: 'R-ELEMENT',
    check: (ctx) =>
      ctx.tokens
        .filter((t) => !allowedElement(t.name, ctx.stage))
        .map((t) => refusal('R-ELEMENT', at(t), `<${t.name}> is not an element this document may contain`)),
  },
  {
    id: 'R-ATTRIBUTE',
    check: (ctx) =>
      ctx.tokens.flatMap((token) => {
        const known = allowedElement(token.name, ctx.stage)
        return token.attrs
          .filter(
            (attr) =>
              alwaysRefused(attr.name) || (known && !mayCarry(token.name, attr.name, ctx.stage)),
          )
          .map((attr) =>
            refusal(
              'R-ATTRIBUTE',
              at(token),
              `${attr.name} is not an attribute <${token.name}> may carry: ` +
                `${attr.name}="${attr.value.slice(0, 60)}"`,
            ),
          )
      }),
  },
  {
    id: 'R-VALUE',
    check: (ctx) =>
      ctx.tokens.flatMap((token) => {
        if (!allowedElement(token.name, ctx.stage)) return []
        const attrs = attributesOf(token)
        const wrong = (detail) => [refusal('R-VALUE', at(token), detail)]
        if (token.name === 'input') {
          const type = attrs.get('type')
          return type === 'file' || type === 'text'
            ? []
            : wrong(`an input may only be of type file or text, not ${type ?? 'none'}`)
        }
        if (token.name === 'button') {
          const type = attrs.get('type')
          return type === 'button' ? [] : wrong(`a button must declare type=button, not ${type ?? 'none'}`)
        }
        if (token.name === 'script') {
          const type = attrs.get('type')
          if (type !== 'module') return wrong(`the only script is an inline module, not type=${type ?? 'none'}`)
          if (ctx.stage === 'source') {
            const src = attrs.get('src')
            if (src !== '/src/main.ts')
              return wrong(`the source shell references its module as /src/main.ts, not ${src ?? 'none'}`)
          }
          return []
        }
        return []
      }),
  },
  {
    id: 'R-META',
    check: (ctx) => {
      const out = []
      const head = first(ctx, 'head')
      const body = first(ctx, 'body')
      const headEnd = ctx.endTags.find((t) => t.name === 'head')
      const firstAfterHead =
        head === undefined ? undefined : ctx.tokens[ctx.tokens.indexOf(head) + 1]
      for (const token of ctx.tokens) {
        if (token.name !== 'meta') continue
        const shape = metaShape(token, ctx)
        if (shape === null) {
          out.push(
            refusal(
              'R-META',
              at(token),
              'a meta this document has no shape for: ' +
                token.attrs.map((a) => `${a.name}="${a.value.slice(0, 60)}"`).join(' '),
            ),
          )
          continue
        }
        // Shape is not enough: a policy the browser reads after the script it should
        // govern governs nothing, and a charset it reads after deciding the encoding is
        // a charset it has already ignored.
        if (shape === 'charset') {
          if (firstAfterHead !== token)
            out.push(refusal('R-META', at(token), 'the charset is not the first thing in the head'))
          else if (token.location.startOffset >= 1024)
            out.push(
              refusal(
                'R-META',
                at(token),
                `the charset sits at byte ${token.location.startOffset}, past the window a browser prescans`,
              ),
            )
        }
        if (shape === 'policy') {
          const start = token.location.startOffset
          const later = ctx.tokens.filter(
            (t) => (t.name === 'script' || t.name === 'style') && t.location.startOffset < start,
          )
          if (head === undefined || start < head.location.startOffset)
            out.push(refusal('R-META', at(token), 'the policy sits outside the head'))
          else if (body !== undefined && start > body.location.startOffset)
            out.push(refusal('R-META', at(token), 'the policy sits in the body, where it does not apply'))
          else if (headEnd !== undefined && start > headEnd.location.startOffset)
            out.push(refusal('R-META', at(token), 'the policy sits after the head is closed'))
          else if (later.length > 0)
            out.push(
              refusal(
                'R-META',
                at(token),
                `the policy sits after the <${later[0].name}> it should govern`,
              ),
            )
        }
      }
      return out
    },
  },
  {
    id: 'R-COUNT',
    check: (ctx) => {
      const seen = (name) => ctx.tokens.filter((t) => t.name === name).length
      const shapes = ctx.tokens.filter((t) => t.name === 'meta').map((t) => metaShape(t, ctx))
      const shaped = (id) => shapes.filter((s) => s === id).length
      const expected = [
        ['<script>', seen('script'), 1],
        ['<title>', seen('title'), 1],
        ['<head>', seen('head'), 1],
        ['<body>', seen('body'), 1],
        ['the charset meta', shaped('charset'), 1],
        ['the viewport meta', shaped('viewport'), 1],
      ]
      if (ctx.stage === 'artifact') {
        expected.push(['<style>', seen('style'), 1], ['the policy meta', shaped('policy'), 1])
      }
      return expected
        .filter(([, found, want]) => found !== want)
        .map(([what, found, want]) =>
          refusal('R-COUNT', `document@0`, `${what}: found ${found}, this document carries ${want}`),
        )
    },
  },
  urlRule('R-URL', ['unparseable', 'scheme', 'userinfo']),
  urlRule('R-URL-CANONICAL', ['canonical']),
  {
    id: 'R-REF',
    check: (ctx) => {
      const ids = idsOf(ctx)
      const dangling = anchors(ctx)
        .filter(({ verdict }) => verdict.reason === 'missing-target')
        .map(({ token, verdict }) =>
          refusal('R-REF', at(token), `${verdict.value} names nothing in this document`),
        )
      const labels = ctx.tokens
        .filter((t) => t.name === 'label')
        .flatMap((token) => {
          const target = attributesOf(token).get('for')
          if (target === undefined || ids.has(target)) return []
          return [refusal('R-REF', at(token), `for="${target}" names no control in this document`)]
        })
      return [...dangling, ...labels]
    },
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
