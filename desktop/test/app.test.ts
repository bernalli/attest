// @vitest-environment jsdom
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL as NodeURL } from 'node:url'
import { unzipSync, zipSync } from 'fflate'
import { loadsStrict, canonicalBytes } from 'attest-verifier'
import { initDesktopApp } from '../src/app.js'
import { MAX_STORED_BYTES } from '../../site/src/container.js'
import type { RuleId } from '../tools/shell-policy.mjs'
import { validateShell } from '../tools/shell-policy.mjs'
import type { Where } from './helpers/shell-mutants.js'
import { mutantMarkup, plant } from './helpers/shell-mutants.js'

const SAMPLE = fileURLToPath(new NodeURL('../../site/public/sample/demo.attest', import.meta.url))
const SHELL = fileURLToPath(new NodeURL('../index.html', import.meta.url))
const TRUST_STORE_VECTOR = fileURLToPath(
  new NodeURL('../../docs/spec/vectors/01-valid-minimal/manifests.json', import.meta.url),
)
const sampleBytes = () => new Uint8Array(readFileSync(SAMPLE))

// The shell is read FROM DISK, not built by the test. That is the whole point: an
// earlier version of this suite assembled the markup from a string the module exported,
// which meant the test performed, in order to prepare itself, the very action a dead
// script cannot perform — and so proved nothing about the case it named.
const shellHtml = () => readFileSync(SHELL, 'utf8')
const shellBody = () => shellHtml().replace(/[\s\S]*<body>/i, '').replace(/<\/body>[\s\S]*/i, '')

// The card renderer is mocked ONLY to make a job throw on demand. Its throw is a real
// contract pinned in card-hostile.test.ts; what no test covered is whether the APP
// survives it — measured, removing the per-job catch left the whole suite green.
const throwFor = vi.hoisted(() => new Set<string>())

vi.mock('../src/card.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/card.js')>()
  return {
    ...actual,
    renderDesktopCard(...args: Parameters<typeof actual.renderDesktopCard>) {
      if (throwFor.has(args[0].label))
        throw new Error('desktop card: expected one .verdict node to replace, found 0')
      return actual.renderDesktopCard(...args)
    },
  }
})

function member(prefix: string): Uint8Array {
  const found = unzipSync(sampleBytes())
  const name = Object.keys(found).find((n) => n.startsWith(prefix))
  if (!name) throw new Error(`the sample bundle has no ${prefix} member`)
  return found[name]
}
const containerBytes = () => member('manifests/')
const bareEnvelope = () => member('receipts/')

// The deal the sample's receipt refers to, under the name it travelled with. An
// importer refuses a bundle that names a legal text it does not carry, so a
// hand-built bundle around that receipt has to bring this along — taken from the
// sample rather than written here, because the digest has to be the real one.
const legalMember = (): [string, Uint8Array] => {
  const found = unzipSync(sampleBytes())
  const name = Object.keys(found).find((n) => n.startsWith('legal/'))
  if (!name) throw new Error('the sample bundle has no legal/ member')
  return [name, found[name]]
}

const receiptLabel = (): string => {
  const found = unzipSync(sampleBytes())
  const name = Object.keys(found).find((n) => n.startsWith('receipts/'))!
  return name.slice('receipts/'.length, -'.attest.json'.length)
}

function singleKeyManifest(): Uint8Array {
  const container = JSON.parse(new TextDecoder().decode(containerBytes()))
  return canonicalBytes(
    loadsStrict(new TextEncoder().encode(JSON.stringify(container.key_manifests[0]))),
  )
}

// A bundle with TWO receipts. The repo has none — every .attest in it carries exactly
// one — so "a card per receipt" would otherwise be a claim about n = 1, and the
// cross-pairing hazard the card's signature exists to prevent could not be exercised.
//
// The second is the first with its receipt_id altered, which breaks its signature. That
// is deliberate and is the scenario worth pinning: a bundle where one receipt is sound
// and one is not. (Cloning the receipt verbatim is impossible by design — the parser
// refuses a bundle that lists the same receipt_id twice.)
const SECOND_ID = '01M0YX8RAPJ5BQ8WJSS4CBK43G'
function twoReceiptBundle(): Uint8Array {
  const first = bareEnvelope()
  const altered = new TextDecoder().decode(first).replace(receiptLabel(), SECOND_ID)
  const [legalName, legalText] = legalMember()
  return zipSync({
    [`receipts/${receiptLabel()}.attest.json`]: first,
    [`receipts/${SECOND_ID}.attest.json`]: new TextEncoder().encode(altered),
    'manifests/m.json': containerBytes(),
    [legalName]: legalText,
  })
}

function mount() {
  document.body.innerHTML = shellBody()
  return initDesktopApp(document)
}

const resultsText = () => document.getElementById('results')?.textContent ?? ''

beforeEach(() => {
  throwFor.clear()
  document.body.innerHTML = ''
})

describe('the page says so when its script never runs', () => {
  test('the banner is in the shipped markup, not assembled by the script', () => {
    // Read as text, before any DOM: this is what a browser gets when the script is
    // blocked. If the banner were built in JavaScript this assertion could not exist.
    expect(shellHtml()).toMatch(/id="boot-failsafe"/)
    expect(shellHtml()).toMatch(/did not start/i)
    expect(shellHtml()).toMatch(/aria-disabled="true"/)
  })

  test('the banner exists exactly once — a second copy would outlive the fix', () => {
    // The mirror-image defect: the script removes one node, so a working app would show
    // the leftover "this verifier did not start" for ever.
    expect(shellHtml().match(/id="boot-failsafe"/g)).toHaveLength(1)
  })

  test('starting the app clears the banner and enables the dropzone', () => {
    document.body.innerHTML = shellBody()
    expect(document.getElementById('boot-failsafe')).not.toBeNull()
    initDesktopApp(document)
    expect(document.getElementById('boot-failsafe')).toBeNull()
    expect(document.getElementById('dropzone')?.getAttribute('aria-disabled')).toBeNull()
  })

  test('a shell missing a wired element throws with the banner still up', () => {
    // The ordering that matters: the banner is cleared LAST, so a failure part-way
    // through the wiring leaves the page saying it did not start.
    document.body.innerHTML = shellBody().replace(/<div id="results"><\/div>/, '')
    expect(() => initDesktopApp(document)).toThrow(/results/)
    expect(document.getElementById('boot-failsafe')).not.toBeNull()
  })

  // The shell used to be checked by a COPY of the build's markup rules, kept in step
  // with them by hand. It is checked by the rules themselves now: one policy, two
  // callers. A replica that drifts is a test that passes about the wrong thing.
  test('the shell fetches nothing while the browser parses it', () => {
    expect(validateShell(readFileSync(SHELL), { stage: 'source' })).toEqual([])
  })

  test('the same rules name each construct when it is present (negative self-test)', () => {
    // An absence assertion whose rules have quietly stopped matching passes for ever
    // while proving nothing — the failure that looks exactly like success.
    const planted: Array<[string, Where, string, RuleId]> = [
      ['a meta refresh', 'HEAD', mutantMarkup(1), 'R-META'],
      ['an image in the head', 'HEAD', mutantMarkup(8), 'R-ELEMENT'],
      ['a meta refresh inside the select', 'SELECT', mutantMarkup(40), 'R-META'],
      ['a javascript href', 'BODY', mutantMarkup(47), 'R-URL'],
      ['the allowed link as a character reference', 'ANCHOR', mutantMarkup(67), 'R-URL-CANONICAL'],
    ]
    for (const [what, where, markup, rule] of planted) {
      const grown = plant(shellHtml(), where, markup)
      const refusals = validateShell(Buffer.from(grown.html, 'utf8'), { stage: 'source' })
      expect(refusals.map((r) => r.rule), `not caught: ${what}`).toContain(rule)
    }
  })

  test('the shell does carry the anchor the carve-out exists for', () => {
    expect([...shellHtml().matchAll(/<a\b[^>]*\shref=/gi)].length).toBeGreaterThan(0)
  })

  test('the shell carries no leftover of the sample receipt', () => {
    // Kept from the predicate this block replaced: it is not a self-fetching rule, and
    // dropping it silently with the rest would have lost a kill nobody was watching.
    expect(shellHtml()).not.toMatch(/sample/i)
  })
})

describe('a bearer file is refused by name, and the reason is the risk', () => {
  test('dropping a .private.attest is refused before anything is parsed', () => {
    const app = mount()
    app.handleBytes('holiday.private.attest', new Uint8Array([1, 2, 3]))
    expect(resultsText()).toMatch(/never share/i)
    expect(resultsText()).not.toMatch(/offline check can go/i)
  })

  test('a refusal cancels a half-finished handover instead of leaving it live', () => {
    const app = mount()
    app.handleBytes('receipt.attest.json', bareEnvelope())
    app.handleBytes('holiday.private.attest', new Uint8Array([1, 2, 3]))
    // Measured before the fix: the pending envelope survived its own refusal, and a
    // later manifest replaced the bearer warning with that receipt's verdict.
    app.handleManifestBytes(singleKeyManifest())
    expect(resultsText()).toMatch(/never share/i)
    expect(resultsText()).not.toMatch(/offline check can go/i)
    expect(document.querySelectorAll('.component-value')).toHaveLength(0)
  })
})

describe('a receipt this app cannot render never becomes a blank page', () => {
  test('the job that throws becomes a fault card; the reason is shown, not buried', () => {
    const app = mount()
    app.handleBytes('demo.attest', sampleBytes())
    expect(document.querySelectorAll('.result').length).toBeGreaterThan(0)

    throwFor.add(receiptLabel())
    app.handleBytes('demo.attest', sampleBytes())

    expect(resultsText()).toMatch(/could not check this receipt/i)
    expect(resultsText(), 'the reason must reach the reader').toMatch(/\.verdict node/)
    // Whatever the app says here, it must not be reassuring: nothing was examined.
    expect(resultsText()).not.toMatch(/Receipt verifies/)
    expect(resultsText()).not.toMatch(/Checks out/)
  })

  test('one broken receipt does not take its neighbour down', () => {
    const app = mount()
    throwFor.add('01M0YX8RAPJ5BQ8WJSS4CBK43F')
    app.handleBytes('two.attest', twoReceiptBundle())
    expect(resultsText()).toMatch(/could not check this receipt/i)
    // The other one still produced a verdict: that is what per-job isolation means.
    expect(document.querySelectorAll('.verdict').length).toBeGreaterThan(0)
  })

  test('a second file replaces the first, never renders below it', () => {
    const app = mount()
    app.handleBytes('demo.attest', sampleBytes())
    const first = document.querySelectorAll('.result').length
    app.handleBytes('demo.attest', sampleBytes())
    expect(document.querySelectorAll('.result')).toHaveLength(first)
  })
})

describe('an optional field typed wrong does not cost you the verdict', () => {
  test('a mistyped salt reports itself WITHOUT clearing the cards', () => {
    const app = mount()
    app.handleBytes('demo.attest', sampleBytes())
    const before = document.querySelectorAll('.result').length
    expect(before).toBeGreaterThan(0)

    const saltField = document.getElementById('binding-salt') as HTMLInputElement
    saltField.value = '!!! not base64url !!!'
    app.applyDisclosure()

    expect(resultsText()).toMatch(/base64url/i)
    expect(document.querySelectorAll('.result'), 'a typo must not erase the verdict').toHaveLength(before)
  })

  test('pressing Check with nothing loaded answers, rather than doing nothing', () => {
    const app = mount()
    app.applyDisclosure()
    expect(resultsText()).toMatch(/no receipt open/i)
  })

  test('an empty identifier is refused instead of silently proving nothing', () => {
    const app = mount()
    app.handleBytes('demo.attest', sampleBytes())
    ;(document.getElementById('binding-salt') as HTMLInputElement).value = 'AAAA'
    app.applyDisclosure()
    expect(resultsText()).toMatch(/email address or account id/i)
  })
})

// v0.1 §14.4: the spend is bounded before the container is analysed. This app runs
// from a file:// URL on whatever machine a holder still has, which is the machine
// least able to afford a copy of a file it was never going to read.
describe('a file over the stored floor is refused before it is copied', () => {
  const fileOfSize = (name: string, size: number, arrayBuffer: () => Promise<ArrayBuffer>): File =>
    ({ name, size, arrayBuffer }) as unknown as File

  const drop = (file: File): void => {
    const event = new Event('drop') as Event & { dataTransfer: unknown }
    Object.defineProperty(event, 'dataTransfer', { value: { files: [file] } })
    document.getElementById('dropzone')!.dispatchEvent(event)
  }

  test('never asks for the bytes of a file over the floor', async () => {
    void mount()
    const bytes = vi.fn(() => Promise.resolve(new ArrayBuffer(0)))
    drop(fileOfSize('huge.attest', MAX_STORED_BYTES + 1, bytes))
    await new Promise((r) => setTimeout(r, 0))
    expect(bytes).not.toHaveBeenCalled()
  })

  test('shows the neutral register, never the bad one, for a file it did not read', async () => {
    void mount()
    drop(
      fileOfSize('huge.attest', MAX_STORED_BYTES + 1, () => Promise.resolve(new ArrayBuffer(0))),
    )
    await new Promise((r) => setTimeout(r, 0))
    const classes = [...document.getElementById('results')!.querySelectorAll('*')].map(
      (node) => node.className,
    )
    expect(classes).toContain('verdict tone-neutral')
    expect(classes).not.toContain('verdict tone-bad')
    expect(resultsText()).not.toMatch(/invalid|corrupt|tampered/i)
  })

  test('does not name the file it refused', async () => {
    void mount()
    drop(
      fileOfSize('Your receipt is valid.attest', MAX_STORED_BYTES + 1, () =>
        Promise.resolve(new ArrayBuffer(0)),
      ),
    )
    await new Promise((r) => setTimeout(r, 0))
    expect(resultsText()).not.toContain('Your receipt is valid')
  })

  test('still reads a file at exactly the floor', async () => {
    void mount()
    const bytes = vi.fn(() => Promise.resolve(sampleBytes().buffer as ArrayBuffer))
    drop(fileOfSize('library.attest', MAX_STORED_BYTES, bytes))
    await new Promise((r) => setTimeout(r, 0))
    expect(bytes).toHaveBeenCalledTimes(1)
  })
})

describe('a file that cannot be read is said, not swallowed', () => {
  test('a rejected read leaves a message rather than an empty pane', async () => {
    const app = mount()
    void app
    const dropzone = document.getElementById('dropzone')!
    const file = {
      name: 'gone.attest',
      arrayBuffer: () => Promise.reject(new Error('NotReadableError')),
    } as unknown as File
    const event = new Event('drop') as Event & { dataTransfer: unknown }
    Object.defineProperty(event, 'dataTransfer', { value: { files: [file] } })
    dropzone.dispatchEvent(event)

    await new Promise((r) => setTimeout(r, 0))
    expect(resultsText()).toMatch(/could not read that file/i)
  })
})

describe('the refusal names the difference for every shape it can be handed', () => {
  const enc = (s: string) => new TextEncoder().encode(s)
  const withBom = (b: Uint8Array) => {
    const c = new Uint8Array(b.length + 3)
    c.set([0xef, 0xbb, 0xbf])
    c.set(b, 3)
    return c
  }
  const LIE = /is not an attest key list/

  // Every row is a file that IS a key list, refused for a canonical-form reason. The
  // message must never deny the two fields the file demonstrably has.
  const canonicalFormOnly: [string, () => Uint8Array][] = [
    ['a UTF-8 BOM an editor added', () => withBom(singleKeyManifest())],
    [
      'a repeated field name',
      () => enc('{"issuer":"attacker.example",' + new TextDecoder().decode(singleKeyManifest()).slice(1)),
    ],
    [
      'one byte that is not UTF-8',
      () => {
        const b = singleKeyManifest()
        const c = new Uint8Array(b)
        c[10] = 0xff
        return c
      },
    ],
  ]
  for (const [what, bytes] of canonicalFormOnly) {
    test(`${what}: refused, but not by denying the fields it has`, () => {
      const app = mount()
      app.handleBytes('receipt.attest.json', bareEnvelope())
      app.handleManifestBytes(bytes())
      expect(resultsText(), 'the file has issuer and keys; saying otherwise is a lie').not.toMatch(LIE)
    })
  }

  const shapes: [string, () => Uint8Array, RegExp][] = [
    ['the whole bundle, dropped where the page just sent them', () => sampleBytes(), /bundle/i],
    ['the container a bundle keeps inside it', () => containerBytes(), /key_manifests/],
    ['a pre-built trust store', () => new Uint8Array(readFileSync(TRUST_STORE_VECTOR)), /trust store|indexed by seller/i],
    ['a container with only artifact_manifests', () => enc('{"artifact_manifests":{}}'), /trust store|indexed by seller/i],
    ['issuer without keys', () => enc('{"issuer":"store.example.com"}'), /no "keys"|nothing in it/i],
    ['keys without issuer', () => enc('{"keys":[]}'), /which issuer|whose/i],
    ['issuer is a number', () => enc('{"issuer":1,"keys":[]}'), /shape a key list needs/i],
    ['keys is an object, not a list', () => enc('{"issuer":"store.example.com","keys":{}}'), /shape a key list needs/i],
    ['a bare array', () => enc('[1,2,3]'), /issuer/i],
    ['a bare string', () => enc('"hello"'), /issuer/i],
    ['null', () => enc('null'), /issuer/i],
    ['an empty file', () => new Uint8Array(), /not JSON/i],
    ['a truncated key list', () => singleKeyManifest().slice(0, 40), /not JSON/i],
  ]
  for (const [what, bytes, expected] of shapes) {
    test(`${what}: the message names what it is`, () => {
      const app = mount()
      app.handleBytes('receipt.attest.json', bareEnvelope())
      app.handleManifestBytes(bytes())
      expect(resultsText()).toMatch(expected)
      expect(resultsText().trim()).not.toMatch(/^invalid\.?$/i)
    })
  }
})

describe('the manifest handover produces a verdict', () => {
  test('a bare envelope plus its key manifest renders one card', () => {
    const app = mount()
    app.handleBytes('receipt.attest.json', bareEnvelope())
    expect(document.querySelectorAll('.result')).toHaveLength(0)

    app.handleManifestBytes(singleKeyManifest())
    expect(document.querySelectorAll('.result')).toHaveLength(1)
    expect(document.querySelectorAll('.verdict')).toHaveLength(1)
    expect(resultsText()).not.toContain('Receipt verifies')
  })

  test('the card still names the file that was dropped, not the manifest and not nothing', () => {
    // The handover renders a card built long after the drop, from state the app carried
    // across two events. The name of the dropped file is part of that state, and it is
    // the one string on the card the signature does not cover — so losing it here shows
    // up as a card that says "File you dropped: undefined" to a reader who dropped one.
    const app = mount()
    app.handleBytes('bare-receipt.attest.json', bareEnvelope())
    app.handleManifestBytes(singleKeyManifest())

    const supplied = document.querySelector('.supplied-name')?.textContent
    expect(supplied).toBeTruthy()
    expect(supplied).toContain('bare-receipt.attest.json')
    expect(supplied).not.toContain('undefined')
  })
})

describe('a bundle renders a card per receipt, each with its own headline', () => {
  test('two receipts produce two cards and two headlines', () => {
    const app = mount()
    app.handleBytes('two.attest', twoReceiptBundle())
    const cards = document.querySelectorAll('.result')
    expect(cards).toHaveLength(2)
    expect(document.querySelectorAll('.verdict')).toHaveLength(2)
    // One sound, one whose signature the alteration broke: the binary headline must not
    // appear for either, and both must have been rendered.
    expect(resultsText()).not.toContain('Receipt verifies')
    expect(resultsText()).toMatch(/does NOT verify/i)
  })

  test('the card is titled from the payload, not from the file name it arrived under', () => {
    const app = mount()
    app.handleBytes('VERIFIED by Steam - Genuine.attest', sampleBytes())
    const title = document.querySelector('.result h3')?.textContent
    // No `?? ''`: a missing card must fail this test, not satisfy it.
    expect(title).toBeTruthy()
    expect(title).not.toContain('Steam')
  })
})

// T5.4 / T5.4-bis: the four evidence rails of v0.1 §14.3, one slot each,
// replaced and never merged, surviving the receipts drawn against them.
describe('the four evidence rails: one slot each, replaced never merged, refused independently', () => {
  const bytesOf = (t: string) => new TextEncoder().encode(t)
  const railText = () => document.querySelector('p.rails')?.textContent ?? ''
  const loadReceipt = (app: ReturnType<typeof mount>, fileName = 'r.attest.json'): void => {
    app.handleBytes(fileName, bareEnvelope())
    app.handleManifestBytes(singleKeyManifest())
  }

  test('a rail dropped before any receipt is held, not lost, once one arrives', () => {
    const app = mount()
    // Must not throw: the rails outlive the receipts on screen by design, and
    // that has to hold even when a rail arrives FIRST, with nothing yet to
    // render it against.
    expect(() => app.handleBytes('revocation-view.json', bytesOf('[]'))).not.toThrow()
    loadReceipt(app)
    expect(railText()).toContain('Revocation feed: 0 records')
  })

  // §14.3's whole point: the RESULT reports `unknown` for both an absent rail
  // and an empty one, so the two states have to read differently somewhere —
  // here, on the rail line itself.
  test('no file at all and an empty array say different things', () => {
    const app = mount()
    loadReceipt(app)
    expect(railText()).toContain('no revocation feed loaded')

    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(railText()).toContain('Revocation feed: 0 records')
  })

  test('a second drop on the same rail replaces it outright, it never merges with the first', () => {
    const app = mount()
    loadReceipt(app)
    app.handleBytes('transfer-view.json', bytesOf('[{"a":1}]'))
    app.handleBytes('transfer-view.json', bytesOf('[]'))
    expect(railText()).toContain('Transfer view: 0 claims')
  })

  test('a refused rail file leaves the receipt card on screen, naming the file it refused', () => {
    const app = mount()
    loadReceipt(app)
    const before = document.querySelectorAll('article.result:not(.rejected)').length
    expect(before).toBeGreaterThan(0)

    app.handleBytes('revocation-view.json', bytesOf('null'))
    // `null` reads as an opt-out to a careless reader, and is exactly the one
    // input §14.3 singles out as NOT one — the message has to name the file.
    expect(resultsText()).toContain('revocation-view.json')
    expect(document.querySelectorAll('article.result:not(.rejected)')).toHaveLength(before)
  })

  test('a refused rail does not clear what the SAME rail held before the refusal', () => {
    const app = mount()
    loadReceipt(app)
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    app.handleBytes('revocation-view.json', bytesOf('null'))
    expect(railText()).toContain('Revocation feed: 0 records')
  })

  test('clearRails resets all four slots to "not consulted"', () => {
    const app = mount()
    loadReceipt(app)
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    app.clearRails()
    expect(railText()).toContain('no revocation feed loaded')
  })

  test('the shell’s Clear feeds button is wired to the same reset', () => {
    const app = mount()
    loadReceipt(app)
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    const btn = document.getElementById('clear-feeds')
    expect(btn).toBeInstanceOf(HTMLButtonElement)
    ;(btn as HTMLButtonElement).click()
    expect(railText()).toContain('no revocation feed loaded')
  })

  test('a rail file’s own name never displaces the receipt’s name on the card', () => {
    const app = mount()
    loadReceipt(app, 'my-receipt.attest.json')
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(resultsText()).not.toContain('revocation-view.json')
    expect(resultsText()).toContain('my-receipt.attest.json')
  })

  test('the four slots are independent: one refusal disturbs none of the other three', () => {
    const app = mount()
    loadReceipt(app)
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    app.handleBytes('transfer-view.json', bytesOf('[]'))
    app.handleBytes('compromise-view.json', bytesOf('[]'))
    app.handleBytes('revocation-evidence.json', bytesOf('{}'))
    const before = railText()
    expect(before).toContain('Revocation feed: 0 records')
    expect(before).toContain('Transfer view: 0 claims')
    expect(before).toContain('Compromise view: 0 claims')
    expect(before).toContain('Revocation evidence: loaded')

    app.handleBytes('transfer-view.json', bytesOf('null'))
    const after = railText()
    expect(after).toContain('Revocation feed: 0 records')
    expect(after).toContain('Compromise view: 0 claims')
    expect(after).toContain('Revocation evidence: loaded')
  })

  test('a rail drop does not retract a binding proof the reader already gave', () => {
    // §14.3 makes a rail file a change to that rail and nothing else. Re-verifying
    // with no disclosure prints "Nobody attempted the binding proof" over a proof
    // that was given and succeeded — the surface asserting the opposite of its own
    // state, which is the defect this rail wiring exists to close. The site keeps
    // this state; two shells over one intake must not disagree about one gesture.
    //
    // The sentence is asserted by the text `explain.ts` actually renders. It used
    // to read "Nobody attempted to prove who this receipt belongs to", which v0.1
    // §11.1 now forbids a surface from saying; an assertion left on the retired
    // wording would be green because the sentence is gone, not because the proof
    // survived.
    const app = mount()
    loadReceipt(app)
    ;(document.getElementById('binding-identifier') as HTMLInputElement).value = 'buyer@example.com'
    ;(document.getElementById('binding-salt') as HTMLInputElement).value = 'AAAA'
    app.applyDisclosure()
    expect(resultsText()).not.toContain('Nobody attempted the binding proof')

    app.handleBytes('revocation-view.json', new TextEncoder().encode('[]'))
    expect(resultsText()).not.toContain('Nobody attempted the binding proof')

    app.clearRails()
    expect(resultsText()).not.toContain('Nobody attempted the binding proof')
  })

  test('a NEW receipt does drop the previous binding proof', () => {
    // The other half: the disclosure belongs to the jobs it was applied to, and
    // must not survive them.
    const app = mount()
    loadReceipt(app)
    ;(document.getElementById('binding-identifier') as HTMLInputElement).value = 'buyer@example.com'
    ;(document.getElementById('binding-salt') as HTMLInputElement).value = 'AAAA'
    app.applyDisclosure()
    loadReceipt(app)
    expect(resultsText()).toContain('Nobody attempted the binding proof')
  })

  test('does not erase the bearer-file refusal when a rail file arrives after it', () => {
    // Measured before this guard existed: the `.private.attest` refusal — the one
    // sentence this app most needs to leave on screen — was wiped by a perfectly
    // valid revocation-view.json dropped next, and the pane went blank.
    const app = mount()
    app.handleBytes('secrets.private.attest', bytesOf('anything'))
    expect(resultsText()).toContain('Never share')
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(resultsText()).toContain('Never share')
  })

  test('does not erase the key-list handover while the handover is still open', () => {
    const app = mount()
    app.handleBytes('r.attest.json', bareEnvelope())
    expect(document.getElementById('manifest-zone')!.hidden).toBe(false)
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(document.getElementById('manifest-zone')!.hidden).toBe(false)
    expect(resultsText()).toContain('key list')
  })

  test('acknowledges a rail accepted with no receipt on screen', () => {
    // Silence is the one answer a verifier may never give: a rail accepted with
    // nothing to qualify still has to say that it was accepted.
    const app = mount()
    app.handleBytes('revocation-view.json', bytesOf('[]'))
    expect(resultsText()).toContain('Revocation feed: 0 records')
  })
})
