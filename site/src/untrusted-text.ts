// One character policy for every untrusted string this page renders inside a
// quoted boundary. Grown out of bundle.ts's quoted(): the double quote, C0/C1
// controls, and every Unicode format character (Cf) — bidi overrides and
// isolates, the zero-width family, the BOM — plus the curly double quotes that
// explain.ts uses as its own in-band quoting.
//
// Replaced, never dropped, so a string that carried one is visibly not the
// string on the wire. Dropping would let an attacker write a sentence that
// reads clean once the removal has happened.
//
// Why one module rather than one rule per call site: the first correction to
// either copy is where two copies start to differ, and this project has paid
// for that lesson on its normative texts more than once. The callers differ
// only in how they quote — in-band `"…"` for a composed message, a structural
// <q> element in the DOM — and in the cap they choose.
//
// What this does NOT defend against, stated because a reader will assume it
// does: RTL *letters* are not Cf, so Hebrew and Arabic pass through untouched
// and can still reorder the words around them. Only `unicode-bidi: isolate` in
// the stylesheet holds that line, no test in this suite can observe its effect,
// and if the stylesheet is not served it is gone (C-91, accepted residual).

export const REPLACEMENT = '\uFFFD'
// Exported WITHOUT the global flag on purpose. `test()` on a global regex
// advances `lastIndex`, and this is a module-level constant every caller
// shares: two guards in a row on the same string answer true, then false, and
// a hostile string reported clean is the exact failure this module exists to
// prevent. The global twin used for replacement is derived from this one, so
// the class is still written down once.
export const HOSTILE_IN_QUOTES = /["\u201c\u201d\u0000-\u001f\u007f-\u009f\p{Cf}]/u
const HOSTILE_ALL = new RegExp(HOSTILE_IN_QUOTES.source, 'gu')

/** Flatten whitespace, replace hostile characters, clip. Returns the bare
 * neutralized text: the caller decides the quoting (in-band `"..."` for
 * composed messages, a structural <q> element for DOM rendering). Clipping
 * counts UTF-16 units — the historical bundle.ts semantics, kept identical. */
//: Real spacing, collapsed to one space so a name cannot open up a message
//: with runs of blanks. Spelled out rather than written `\\s`, and that is
//: the whole point: ECMAScript's `\\s` also matches U+FEFF, so a `\\s`-first
//: flatten turned the BOM into a space before the hostile pass could see it.
//: The library composes a genuine diagnostic that carries one — `invalid
//: JSON: unexpected token '<BOM>' at 0` — and rendering that as a space tells
//: the reader the offending character was a space. Format characters must
//: reach the replacement; only true spacing is collapsed here.
const COLLAPSIBLE_SPACE = /[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/g

const isLeadSurrogate = (unit: number): boolean => unit >= 0xd800 && unit <= 0xdbff

export function neutralized(text: string, maxChars: number): string {
  const flat = text.replace(COLLAPSIBLE_SPACE, ' ').replace(HOSTILE_ALL, REPLACEMENT)
  if (flat.length <= maxChars) return flat
  // Clipping counts UTF-16 units, so the cut can land between the two halves
  // of an astral character — an emoji in a member name. Keeping the orphaned
  // lead unit makes the output not well-formed: it draws as a stray box beside
  // the ellipsis, and it throws in any UTF-8 path a later caller adds. Drop the
  // half instead; one code point under the cap is never the wrong side of it.
  const cut =
    maxChars > 0 && isLeadSurrogate(flat.charCodeAt(maxChars - 1)) ? maxChars - 1 : maxChars
  return `${flat.slice(0, cut)}…`
}
