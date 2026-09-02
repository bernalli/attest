/** jsdom ships no types and this package installs none: the suites have always reached
 *  it through vitest's environment, never through its API. The oracle that pins the
 *  divergence between the token stream and the tree DOES call it directly, so the small
 *  part of its surface that is used is declared here — adding `@types/jsdom` would grow
 *  the installed set, which is exactly what this artifact's argument rests on not doing. */
declare module 'jsdom' {
  export class JSDOM {
    constructor(html: string, options?: { url?: string })
    readonly window: { document: Document }
  }
}
