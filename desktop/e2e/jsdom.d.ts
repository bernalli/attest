/** jsdom ships no types and this package installs none. The oracle that compares the
 *  token stream with the tree calls it directly, so the small part of its surface that
 *  is used is declared here — adding `@types/jsdom` would grow the installed set, which
 *  is the one thing this artifact's argument rests on not doing. */
declare module 'jsdom' {
  export class JSDOM {
    constructor(html: string, options?: { url?: string })
    readonly window: { document: Document }
  }
}
