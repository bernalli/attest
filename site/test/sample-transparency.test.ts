// @vitest-environment jsdom
//
// The gate that keeps the log and the sample from drifting apart.
//
// The committed sample carries a proofs/ member issued by attest's own
// transparency log, and the page carries that log's pinned public keys. Those
// two are produced by different steps — `tools/gen_site_sample.py` writes the
// first, `site/src/trusted-log.ts` holds the second — and nothing but this
// test forces them to agree. Regenerate the sample without logging it, rotate
// the log keys without repinning them, or quietly stop passing the pinned
// configuration, and the page goes back to saying `not_checked` at every
// visitor while every other suite stays green.
//
// So this drives the real page, with the real committed bytes, and demands
// the standing the log actually supports: `logged`, and no further. It must
// NOT reach `witnessed` — no independent witness co-signs these checkpoints,
// and a day when this assertion starts failing upward is a day someone
// widened a claim the log cannot back.
import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { initApp, type AppHandle } from '../src/main.js'
import { LOG_KEYS, LOG_ORIGIN } from '../src/trusted-log.js'

const SAMPLE = join(__dirname, '..', 'public', 'sample', 'demo.attest')

const PAGE = `
  <div id="dropzone"></div><input id="file-input" type="file">
  <div id="manifest-zone" hidden></div><input id="manifest-input" type="file">
  <input id="binding-identifier"><select id="binding-type"><option value="email">email</option></select>
  <input id="binding-salt"><button id="binding-apply"></button>
  <button id="load-sample"></button>
  <section id="results"></section>`

let app: AppHandle
beforeEach(() => {
  document.body.innerHTML = PAGE
  app = initApp(document)
})

describe('the committed sample, checked against the pinned log', () => {
  it('reaches logged — the page proves the log it pins actually holds this receipt', () => {
    app.handleBytes('demo.attest', new Uint8Array(readFileSync(SAMPLE)))
    const text = document.getElementById('results')!.textContent ?? ''
    expect(text).toContain('"transparency": "logged"')
    expect(text).toContain('"corroboration": "logged"')
  })

  it('claims nothing more than the log can back', () => {
    app.handleBytes('demo.attest', new Uint8Array(readFileSync(SAMPLE)))
    const text = document.getElementById('results')!.textContent ?? ''
    // No witness co-signs this log, so this value is unreachable by design.
    expect(text).not.toContain('witnessed')
    // And the receipt still verifies on its own terms, untouched by any of it.
    expect(text).toContain('Receipt verifies')
  })

  it('reports no transparency warning at all for the sample', () => {
    app.handleBytes('demo.attest', new Uint8Array(readFileSync(SAMPLE)))
    const text = document.getElementById('results')!.textContent ?? ''
    expect(text).not.toContain('transparency_')
    expect(text).not.toContain('anchor_')
  })

  it('pins exactly one log, under the origin the checkpoints are signed with', () => {
    expect(LOG_KEYS).toHaveLength(1)
    expect(LOG_KEYS[0].origin).toBe(LOG_ORIGIN)
    expect(LOG_KEYS[0].name).toBe(LOG_ORIGIN)
    expect(LOG_KEYS[0].ed25519Pub).toHaveLength(32)
    expect(LOG_KEYS[0].mldsaPub).toHaveLength(1952)
    // The origin is signed into every checkpoint and can never be changed
    // without orphaning every proof already issued.
    expect(LOG_ORIGIN).toBe('attest-receipts.org/log')
  })
})
