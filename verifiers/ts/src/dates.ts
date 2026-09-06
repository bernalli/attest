// Strict window dates mirror Python strptime '%Y-%m-%dT%H:%M:%SZ'. Revocation
// freshness uses a separate lenient ISO parse (Python fromisoformat). Both fail closed.
const STRICT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/

/** The latest instant BOTH cores can represent, as Unix seconds:
 * 253402300799 is 9999-12-31T23:59:59Z.
 *
 * Python's `datetime` stops at year 9999 while JavaScript's `Date` reaches
 * year 275760, so anything past this bound is accepted by one core and
 * rejected by the other — a divergence of verdict, not of message.
 *
 * This module owns the number for the whole package. It lived in three
 * independent copies before (a cosignature bound, an anchor bound, and a
 * year comparison), and the fourth call site that needed it — the refund
 * window — did not remember it existed. A restated predicate is owned by
 * nobody: import this, never re-declare it. */
export const MAX_REPRESENTABLE_UNIX_SECONDS = 253402300799

export function parseStrictUtc(s: unknown): number | null {
  if (typeof s !== 'string') return null
  const m = STRICT.exec(s)
  if (!m) return null
  const [, y, mo, d, h, mi, se] = m.map(Number) as unknown as number[]
  if (y! === 0) return null
  const back = new Date(Date.UTC(y!, mo! - 1, d!, h!, mi!, se!))
  if (y! >= 1 && y! <= 99) back.setUTCFullYear(y!)
  const t = back.getTime()
  // reject impossible values that Date.UTC would roll over (e.g. month 13, day 32,
  // hour 24, minute 60, second 60) — all six components must round-trip, matching
  // Python strptime '%Y-%m-%dT%H:%M:%SZ' which rejects any out-of-range field.
  if (
    back.getUTCFullYear() !== y! ||
    back.getUTCMonth() !== mo! - 1 ||
    back.getUTCDate() !== d! ||
    back.getUTCHours() !== h! ||
    back.getUTCMinutes() !== mi! ||
    back.getUTCSeconds() !== se!
  )
    return null
  return t
}

/** Whether `value` has the signed UTC wire shape used by Stage 3 side
 * documents (`YYYY-MM-DDTHH:MM:SSZ`) and names a real UTC calendar instant.
 * `parseIsoLenient` delegates to Date.parse, whose timezone-less ISO handling
 * uses the host's local time. */
export function validStage3UtcTimestamp(value: unknown): value is string {
  return typeof value === 'string' && parseStrictUtc(value) !== null
}

export function parseIsoLenient(s: unknown): number | null {
  if (typeof s !== 'string') return null
  const t = Date.parse(s)
  return Number.isNaN(t) ? null : t
}
