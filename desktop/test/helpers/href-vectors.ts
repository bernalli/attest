/**
 * Obfuscated spellings, generated rather than listed.
 *
 * A hand-written list of dangerous spellings shares the blind spots of whoever wrote
 * it — which is how `javascript:` came to be refused three times and got around twice.
 * These are produced mechanically from a base by a closed set of transforms, and the
 * property asserted over all of them is the one that matters: an allowed link has
 * exactly ONE accepted spelling, and everything else is refused.
 */

export interface Variant {
  id: string
  raw: string
}

export interface Transform {
  id: string
  /** Every string this transform produces from `raw`; may be empty when it does not
   *  apply (there is no slash to name, for instance). */
  apply(raw: string): string[]
}

/** Every scheme a browser would follow that this document may not carry, plus the four
 *  shapes that resolve against the file the artifact IS. */
export const REFUSED_BASES: readonly string[] = [
  'javascript:alert(1)',
  'data:text/html,x',
  'vbscript:x',
  '//example.invalid/x',
  'file://example.invalid/share',
  'http://attest-receipts.org/',
  'https://example.invalid/',
  'mailto:x@example.invalid',
  'blob:https://example.invalid/u',
  'about:blank',
  'relative/x.html',
  '?q=1',
  '#nope',
  '',
  'https://a b/',
]

/** The two the document may carry: the footer's link, and a fragment naming an element
 *  the real shell has. Their identity spelling is accepted and nothing else is. */
export const ACCEPTED_BASES: readonly string[] = ['https://attest-receipts.org/', '#dropzone']

export const PAIR_CAP = 40

/** The characters before the first colon — what a browser reads to decide the scheme —
 *  or the whole string when there is none. */
const schemeOf = (raw: string): number => {
  const colon = raw.indexOf(':')
  return colon === -1 ? raw.length : colon
}

const insertEverywhere = (raw: string, what: string): string[] => {
  const end = schemeOf(raw)
  return Array.from({ length: end + 1 }, (_, i) => raw.slice(0, i) + what + raw.slice(i))
}

const replaceEachSchemeChar = (raw: string, spell: (c: string) => string): string[] => {
  const end = schemeOf(raw)
  return Array.from({ length: end }, (_, i) => raw.slice(0, i) + spell(raw[i]) + raw.slice(i + 1))
}

const CONTROLS = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i + 1))

export const TRANSFORMS: readonly Transform[] = [
  { id: 'tab-inside', apply: (raw) => insertEverywhere(raw, '\t') },
  { id: 'lf-inside', apply: (raw) => insertEverywhere(raw, '\n') },
  { id: 'cr-inside', apply: (raw) => insertEverywhere(raw, '\r') },
  // NUL is the one control the URL parser does NOT remove, which is why it is here:
  // it breaks the scheme instead of being spelled around it.
  { id: 'nul-inside', apply: (raw) => insertEverywhere(raw, '\u0000') },
  { id: 'lead-control', apply: (raw) => CONTROLS.map((c) => c + raw) },
  { id: 'trail-control', apply: (raw) => CONTROLS.map((c) => raw + c) },
  { id: 'dec-ref', apply: (raw) => replaceEachSchemeChar(raw, (c) => `&#${c.charCodeAt(0)};`) },
  { id: 'dec-ref-nosemi', apply: (raw) => replaceEachSchemeChar(raw, (c) => `&#${c.charCodeAt(0)}`) },
  {
    id: 'dec-ref-zeros',
    apply: (raw) => replaceEachSchemeChar(raw, (c) => `&#000${c.charCodeAt(0)};`),
  },
  {
    id: 'hex-ref',
    apply: (raw) => replaceEachSchemeChar(raw, (c) => `&#x${c.charCodeAt(0).toString(16)};`),
  },
  {
    id: 'hex-ref-upper',
    apply: (raw) => replaceEachSchemeChar(raw, (c) => `&#X${c.charCodeAt(0).toString(16)};`),
  },
  {
    id: 'named-colon',
    apply: (raw) => (raw.includes(':') ? [raw.replace(':', '&colon;')] : []),
  },
  {
    id: 'named-tab',
    apply: (raw) => {
      const end = schemeOf(raw)
      const out = [`&Tab;${raw}`]
      if (end > 0 && end < raw.length) out.push(`${raw.slice(0, end)}&Tab;${raw.slice(end)}`)
      return out
    },
  },
  {
    id: 'named-newline',
    apply: (raw) => {
      const end = schemeOf(raw)
      const out = [`&NewLine;${raw}`]
      if (end > 0 && end < raw.length) out.push(`${raw.slice(0, end)}&NewLine;${raw.slice(end)}`)
      return out
    },
  },
  // The only transform that reads past the colon: the slashes a browser needs to see an
  // authority are spellable too, and `https:&sol;&sol;host/` is the same link to it.
  { id: 'named-sol', apply: (raw) => (raw.includes('/') ? [raw.split('/').join('&sol;')] : []) },
  {
    id: 'upper',
    apply: (raw) => {
      const end = schemeOf(raw)
      return [raw.slice(0, end).toUpperCase() + raw.slice(end)]
    },
  },
  {
    id: 'alternate',
    apply: (raw) => {
      const end = schemeOf(raw)
      const mixed = raw
        .slice(0, end)
        .split('')
        .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()))
        .join('')
      return [mixed + raw.slice(end)]
    },
  },
]

/** Identity, every single transform, and ordered pairs of two different transforms —
 *  composed on the STRING, so a reference of a tab spells the tab as `&#9;`, a variant
 *  nobody would have written down. */
export function variants(base: string): Variant[] {
  const out: Variant[] = [{ id: 'identity', raw: base }]
  for (const transform of TRANSFORMS)
    transform.apply(base).forEach((raw, i) => out.push({ id: `${transform.id}#${i}`, raw }))
  let pairs = 0
  for (const first of TRANSFORMS)
    for (const second of TRANSFORMS) {
      if (first === second || pairs >= PAIR_CAP) continue
      const once = first.apply(base)[0]
      if (once === undefined) continue
      const twice = second.apply(once)[0]
      if (twice === undefined) continue
      out.push({ id: `${first.id}+${second.id}`, raw: twice })
      pairs += 1
    }
  return out
}

/** The raw spelling goes in VERBATIM, between double quotes: the point of the corpus is
 *  what the source bytes say, so nothing may re-encode them on the way in. */
export const anchorMarkup = (variant: Variant): string => `<a href="${variant.raw}">x</a>`
