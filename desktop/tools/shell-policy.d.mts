/** Declarations for the shell policy, so the suites can import it under `strict`
 *  without turning `allowJs` on for the whole package. */

export type RuleId =
  | 'R-INPUT'
  | 'R-PARSE'
  | 'R-ELEMENT'
  | 'R-ATTRIBUTE'
  | 'R-VALUE'
  | 'R-META'
  | 'R-COUNT'
  | 'R-URL'
  | 'R-URL-CANONICAL'
  | 'R-REF'
  | 'R-CSS'

export interface Refusal {
  rule: RuleId
  where: string
  detail: string
}

export interface Attr {
  name: string
  value: string
}

export interface Span {
  startOffset: number
  endOffset: number
}

export interface TokenLocation extends Span {
  attrs?: Record<string, Span>
}

export interface StartTagToken {
  name: string
  attrs: Attr[]
  location: TokenLocation
}

export interface Tokenized {
  tokens: StartTagToken[]
  endTags: Array<{ name: string; location: TokenLocation }>
  parseErrors: Array<{ code: string; location: Span }>
  document: unknown
  html: string
}

export interface Rule {
  id: RuleId
  check(ctx: Tokenized & { stage: Stage; expectedCsp?: string }): Refusal[]
}

export type Stage = 'artifact' | 'source'

export interface UrlVerdict {
  raw: string
  value: string
  resolved: string | null
  protocol: string | null
  host: string | null
  accepted: boolean
  reason: string
}

export const BASE_URL: string
export const ALLOWED_HOSTS: readonly string[]
export const RULE_IDS: readonly RuleId[]
export const RULES: readonly Rule[]

export function decodeShell(bytes: Uint8Array | Buffer): string
export function tokenizeShell(html: string): Tokenized
export function classifyUrl(raw: string, value: string, ids: ReadonlySet<string>): UrlVerdict
export function scriptAndStyleText(tokenized: Tokenized): {
  script: string | null
  style: string | null
}
export function validateShell(
  bytes: Uint8Array | Buffer,
  options: { stage: Stage; expectedCsp?: string },
  rules?: readonly Rule[],
): Refusal[]
