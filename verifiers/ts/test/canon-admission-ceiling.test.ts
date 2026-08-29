import { describe, expect, it, vi } from 'vitest'

const admission = vi.hoisted(() => ({ ceiling: 0 }))

vi.mock('../src/messages.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/messages.js')>()
  return {
    ...actual,
    codePointLength(value: string): number {
      const measured = new Map<string, number>([
        ['"aaa"', admission.ceiling],
        ['["aaa"]', admission.ceiling + 2],
        ['[["aaa"]]', admission.ceiling + 4],
        ['"aaaa"', admission.ceiling + 1],
        ['["aaaa"]', admission.ceiling + 3],
        ['[["aaaa"]]', admission.ceiling + 5],
      ])
      return measured.get(value) ?? actual.codePointLength(value)
    },
  }
})

import {
  admitValue,
  MAX_ADMISSION_BYTES,
  VIEW_ARRAY_ELEMENT_NESTING,
  VIEW_MEMBER_NESTING,
} from '../src/canon.js'

admission.ceiling = MAX_ADMISSION_BYTES

describe('canon: the admission ceiling is measured on the unit', () => {
  it('admits a unit at the same measured size at every nesting depth', () => {
    for (const nesting of [0, VIEW_MEMBER_NESTING, VIEW_ARRAY_ELEMENT_NESTING]) {
      expect(admitValue('aaa', nesting).admitted).toBe(true)
    }
  })

  it('refuses a unit one code point over the ceiling at every nesting depth', () => {
    for (const nesting of [0, VIEW_MEMBER_NESTING, VIEW_ARRAY_ELEMENT_NESTING]) {
      expect(admitValue('aaaa', nesting).admitted).toBe(false)
    }
  })
})
