import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { decodePng, pixelAt, contrast, parseColour, luminance } from './helpers/pixels.js'

// Contrast on this page is a property of RENDERED PIXELS, and it is not read
// off the stylesheet.
//
// The page's ground is flat now, but the text on it does not sit on one
// colour: the same ink lands on the page, on a white card, on a tinted band,
// on a code chip, on a verdict's tinted box, on a filled button. Which of
// those is under a given run of text is a fact about the rendered layout, and
// an earlier version of this page — a textured paper ground — taught the
// project what modelling it costs: two calculations of the same variable
// disagreed, and neither had looked at a pixel.
//
// The method: render, hide the ink, photograph what is behind it, and measure
// the darkest pixel each piece of text actually covers. It runs once per
// colour scheme, because every token has a second value under
// `prefers-color-scheme: dark` and each of those values is a separate claim.

const AA_SMALL = 4.5
const AA_LARGE = 3
/** WCAG "large text": 18pt (24px), or 14pt (18.66px) at 700. */
const isLarge = (px: number, weight: number): boolean => px >= 24 || (px >= 18.66 && weight >= 700)

// One place, because three things have to agree: the viewport the page is
// laid out in, the distance each step scrolls, and the cut-off that decides
// which rectangles are on screen. Three literal 700s drift apart silently.
const VIEWPORT = { width: 720, height: 700 }

const SCHEMES = ['light', 'dark'] as const
type Scheme = (typeof SCHEMES)[number]

// Every ink the stylesheet puts on text, per scheme, by the colour
// getComputedStyle reports for it. A run that never measured one of these has
// not answered the question it was written for, however many rows it
// collected: deleting the line that empties the inputs, or the click that
// opens the exhibits, drops a whole ink and still leaves ~60 rows behind.
const INKS: Record<Scheme, Record<string, string>> = {
  light: {
    'rgb(31, 27, 22)': '--text',
    'rgb(70, 63, 54)': '--text-2',
    'rgb(95, 87, 75)': '--text-3 (and input::placeholder)',
    'rgb(122, 34, 49)': '--accent',
    'rgb(255, 255, 255)': '--on-accent (filled buttons)',
    'rgb(43, 99, 52)': '--good',
    'rgb(122, 84, 16)': '--warn',
    'rgb(168, 38, 27)': '--bad',
  },
  dark: {
    'rgb(239, 233, 225)': '--text',
    'rgb(211, 203, 191)': '--text-2',
    'rgb(174, 165, 151)': '--text-3 (and input::placeholder)',
    'rgb(237, 164, 173)': '--accent',
    'rgb(36, 9, 13)': '--on-accent (filled buttons)',
    'rgb(143, 209, 156)': '--good',
    'rgb(229, 187, 103)': '--warn',
    'rgb(255, 154, 143)': '--bad',
  },
}

interface Target {
  /** A stable name for the rule that put this text on the page. */
  family: string
  colour: string
  fontSize: number
  weight: number
  box: { x: number; y: number; width: number; height: number }
}

// One rectangle per LINE OF TEXT, not per element. An element's bounding box
// is the wrong shape to ask this question of: it contains the element's own
// border and everything nested inside it, so a button's 1px ink border, a
// link's bordeaux underline and an input's edge all turn up as "the darkest
// pixel behind this sentence" and report a 1:1 failure for text that sits on
// clean paper. The first run of this measurement said exactly that about six
// buttons. A Range over the text node itself covers the line boxes and
// nothing else; the band is then narrowed to the height a glyph occupies.
const collectTargets = (page: Page): Promise<Target[]> =>
  page.evaluate(() => {
    const out: Target[] = []
    const nameOf = (el: Element): string => {
      const tag = el.tagName.toLowerCase()
      if (el.id) return `${tag}#${el.id}`
      const first = String(el.className || '').split(/\s+/).filter(Boolean)[0]
      return first ? `${tag}.${first}` : tag
    }
    /** The band a glyph actually occupies inside a line box. */
    const glyphBand = (rect: DOMRect, fontSize: number) => {
      const height = Math.min(rect.height, fontSize * 1.1)
      return {
        x: rect.x,
        y: rect.y + (rect.height - height) / 2,
        width: rect.width,
        height,
      }
    }

    const range = document.createRange()
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (!(node.textContent ?? '').trim()) continue
      const el = node.parentElement
      if (!el) continue
      const style = getComputedStyle(el)
      if (style.visibility === 'hidden' || style.display === 'none') continue
      // Text inside a shut <details> is not on screen, and its client rects
      // are degenerate: the first run of this measurement reported the raw
      // JSON block at 1:1 against a pixel it never covers. Every <details> is
      // opened before measuring, so this only catches one reopened since.
      if (el.closest('details:not([open])')) continue
      const fontSize = parseFloat(style.fontSize)
      range.selectNodeContents(node)
      for (const rect of range.getClientRects()) {
        if (rect.width < 1 || rect.height < 1) continue
        out.push({
          family: nameOf(el),
          colour: style.color,
          fontSize,
          weight: Number(style.fontWeight) || 400,
          box: glyphBand(rect, fontSize),
        })
      }
    }
    // Placeholders are drawn by a pseudo-element no TreeWalker reaches, and
    // they are the ONE place --ink-faint is used — the variable that prompted
    // this whole measurement. Left out, it would have nothing to say about it.
    // The content box, so the input's own border stays out of the sample.
    for (const input of document.querySelectorAll('input')) {
      if (!input.placeholder || input.value) continue
      const rect = input.getBoundingClientRect()
      const style = getComputedStyle(input)
      const inset = (side: 'Top' | 'Right' | 'Bottom' | 'Left'): number =>
        parseFloat(style[`border${side}Width`]) + parseFloat(style[`padding${side}`])
      const box = {
        x: rect.x + inset('Left'),
        y: rect.y + inset('Top'),
        width: rect.width - inset('Left') - inset('Right'),
        height: rect.height - inset('Top') - inset('Bottom'),
      }
      if (box.width < 1 || box.height < 1) continue
      const placeholder = getComputedStyle(input, '::placeholder')
      out.push({
        family: 'input::placeholder',
        colour: placeholder.color,
        fontSize: parseFloat(placeholder.fontSize || style.fontSize),
        weight: Number(placeholder.fontWeight) || 400,
        box,
      })
    }
    return out
  })

/** Paint every glyph transparent, so a screenshot shows only what is behind. */
const hideInk = (page: Page): Promise<void> =>
  page.evaluate(() => {
    // Through the CSSOM, not a <style> tag: this page's own CSP is
    // `style-src 'self'`, and an injected stylesheet would be refused —
    // which would leave the ink in place and the measurement measuring ink.
    for (const el of document.querySelectorAll<HTMLElement>('*')) {
      el.style.color = 'transparent'
      el.style.setProperty('-webkit-text-fill-color', 'transparent')
      el.style.textDecorationColor = 'transparent'
      el.style.setProperty('caret-color', 'transparent')
    }
  })

/** Put the ink back. The page carries no inline styles of its own — its CSP
 *  forbids them — so clearing these four properties restores the stylesheet. */
const showInk = (page: Page): Promise<void> =>
  page.evaluate(() => {
    for (const el of document.querySelectorAll<HTMLElement>('*')) {
      for (const prop of ['color', '-webkit-text-fill-color', 'text-decoration-color', 'caret-color']) {
        el.style.removeProperty(prop)
      }
    }
  })

for (const scheme of SCHEMES) {
  test(`every piece of text clears its WCAG AA floor where it is printed (${scheme} scheme)`, async ({
    page,
  }, testInfo) => {
    // 720px is where the page's own media query rearranges it and the small
    // text packs tightest; the height is short so the page is photographed in
    // many steps, each covering a band of the layout.
    await page.setViewportSize(VIEWPORT)
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto('/')
    await expect(page.locator('.card__title')).toHaveText('Starlight Drifter')

    // Open everything the bench and the demonstrations can put on the page, so
    // the text they add is measured too rather than skipped for being absent.
    await page.click('#load-sample')
    await expect(page.locator('#bench')).toBeVisible()
    await page.click('#bench-buttons button[data-tamper="title"]')
    await page.click('#run-exhibits')
    await expect(page.locator('.exhibit')).toHaveCount(2)
    await page.click('#run-probe')
    await expect(page.locator('#probe .probe')).toBeVisible()

    // The raw-result blocks are text a reader can put on screen with one click,
    // so they are measured like everything else rather than skipped for being
    // folded away. Opening them changes the page height, so this comes first.
    await page.evaluate(() => {
      for (const details of document.querySelectorAll('details')) details.open = true
      // Loading the sample fills the binding fields, which hides the only
      // placeholders on the page — and placeholders are the sole use of
      // --ink-faint, the lightest ink in the palette and the one this
      // measurement most needs a number for. Emptying them puts the text back
      // on screen and changes nothing else: the verdict already rendered, and
      // nothing re-reads these fields until "Re-verify" is pressed.
      for (const input of document.querySelectorAll('input')) input.value = ''
    })
    const pageHeight = await page.evaluate(() => document.documentElement.scrollHeight)
    const step = VIEWPORT.height
    const worst = new Map<string, { ratio: number; at: string; colour: string; size: number; floor: number }>()

    for (let scroll = 0; scroll < pageHeight; scroll += step) {
      // 'instant', because the page scrolls smoothly for readers who allow motion:
      // an animated scroll would photograph a different band from the one the
      // rectangles were read from.
      await page.evaluate((y) => window.scrollTo({ top: y, behavior: 'instant' }), scroll)
      // Large text is not dropped, only held to its own AA floor of 3:1.
      // Filtering it out here left eight headings — every h2 and both h1 lines —
      // measured by nothing at all.
      const targets = (await collectTargets(page)).filter(
        (t) => t.box.y + t.box.height > 0 && t.box.y < VIEWPORT.height,
      )
      if (targets.length === 0) continue

      await hideInk(page)
      const paper = decodePng(await page.screenshot())
      await showInk(page)

      for (const target of targets) {
        const ink = parseColour(target.colour)
        const x0 = Math.max(0, Math.floor(target.box.x))
        const y0 = Math.max(0, Math.floor(target.box.y))
        // A pixel at index p covers [p, p+1), so the last one the band touches
        // is ceil(end) - 1. Reading ceil(end) inclusively sampled one row past
        // the band, which is where a link's own 1px underline sits: it turned up
        // as "the darkest paper" under the text above it and pulled --bordeaux
        // to 5.22:1 and --ink-2 to 5.24:1, when the paper there is 6.68 and 6.47.
        const x1 = Math.min(paper.width - 1, Math.ceil(target.box.x + target.box.width) - 1)
        const y1 = Math.min(paper.height - 1, Math.ceil(target.box.y + target.box.height) - 1)
        let darkest: [number, number, number] | null = null
        for (let y = y0; y <= y1; y += 1) {
          for (let x = x0; x <= x1; x += 1) {
            const px = pixelAt(paper, x, y)
            if (darkest === null || luminance(px) < luminance(darkest)) darkest = px
          }
        }
        if (darkest === null) continue
        const ratio = contrast(ink, darkest)
        const key = `${target.family} ${target.colour} ${target.fontSize}px`
        const held = worst.get(key)
        if (!held || ratio < held.ratio) {
          worst.set(key, {
            ratio,
            at: `scroll ${scroll}px, background rgb(${darkest.join(', ')})`,
            colour: target.colour,
            size: target.fontSize,
            floor: isLarge(target.fontSize, target.weight) ? AA_LARGE : AA_SMALL,
          })
        }
      }
    }

    const rows = [...worst.entries()].sort((a, b) => a[1].ratio - b[1].ratio)
    const report = rows
      .map(([key, v]) => `${v.ratio.toFixed(2)}:1 (needs ${v.floor})  ${key.padEnd(46)} ${v.at}`)
      .join('\n')
    await testInfo.attach(`contrast-on-rendered-pixels-${scheme}.txt`, { body: report })
    // eslint-disable-next-line no-console
    console.log(`\nmeasured on rendered pixels, 720px viewport, ${scheme} scheme:\n${report}\n`)

    const failing = rows.filter(([, v]) => v.ratio < v.floor)
    expect(
      failing.map(([key, v]) => `${key} — ${v.ratio.toFixed(2)}:1, needs ${v.floor}:1, at ${v.at}`),
      'text below its WCAG AA floor against the darkest paper pixel it covers',
    ).toEqual([])

    // A row count cannot notice a whole surface going missing: the page yields
    // ~66 families, so `> 20` still passed with the exhibits, the probe and
    // every placeholder unmeasured. What has to hold is that each ink actually
    // got looked at.
    const measured = new Set([...worst.values()].map((v) => v.colour))
    expect(
      Object.entries(INKS[scheme])
        .filter(([colour]) => !measured.has(colour))
        .map(([colour, name]) => `${name} ${colour}`),
      'inks the stylesheet puts on text that this run never measured',
    ).toEqual([])

    // And that each demonstration surface actually put its text on the page.
    // Losing one costs ~6 rows out of ~77 and leaves every ink still covered by
    // some other element, so neither the row count nor the ink check above can
    // see it: dropping the exhibits and the probe together still passed both.
    const families = new Set([...worst.keys()].map((key) => key.split(' ')[0]))
    expect(
      ['input::placeholder', 'p.tamper-values', 'p.exhibit-source', 'p.probe-detail'].filter(
        (family) => !families.has(family),
      ),
      'surfaces whose text never reached the measurement',
    ).toEqual([])
  })
}
