// Every leaf of the shared corpus, read by the browser verifier's container
// reader, must produce exactly the verdict the leaf declares — the same verdict
// `tests/test_container_corpus.py` demands from the reference importer.
//
// This file is the whole point of the exercise: "same bytes, same member list"
// stops being an aspiration and becomes a test that fails.

import { describe, expect, it } from 'vitest'
import { canonicalMembers, readMember, ReadBudget, ContainerError, CODES, MESSAGES } from '../src/container.js'
import { archiveBytes, codesTable, expectation, leafNames } from './helpers/container-corpus.js'
import type { CorpusCaps } from './helpers/container-corpus.js'
import { createHash } from 'node:crypto'

type Verdict =
  | { verdict: 'accept'; members: { name: string; method: number; size: number; sha256: string }[] }
  | { verdict: 'reject'; code: string; member: string | null }

function verdictOf(bytes: Uint8Array, caps: CorpusCaps): Verdict {
  try {
    const members = canonicalMembers(bytes, {
      maxEntries: caps.max_entries,
      maxMemberBytes: caps.max_member_bytes,
      maxTotalBytes: caps.max_total_bytes,
    })
    const budget = new ReadBudget(caps.max_member_bytes, caps.max_total_bytes)
    return {
      verdict: 'accept',
      members: members.map((member) => {
        const data = readMember(bytes, member, budget)
        return {
          name: member.name,
          method: member.method,
          size: data.length,
          sha256: createHash('sha256').update(data).digest('hex'),
        }
      }),
    }
  } catch (error) {
    if (error instanceof ContainerError) return { verdict: 'reject', code: error.code, member: error.member }
    throw error
  }
}

describe('container corpus', () => {
  const leaves = leafNames()

  it('has leaves to read', () => {
    expect(leaves.length).toBeGreaterThan(0)
  })

  for (const leaf of leaves) {
    it(`gives ${leaf} the verdict it declares`, () => {
      const expected = expectation(leaf)
      const got = verdictOf(archiveBytes(leaf), expected.caps)
      expect(got.verdict).toBe(expected.verdict)
      if (expected.verdict === 'reject' && got.verdict === 'reject') {
        expect(got.code).toBe(expected.code)
        if (expected.member !== null && expected.member !== undefined) expect(got.member).toBe(expected.member)
      } else if (got.verdict === 'accept') {
        expect(got.members).toEqual(expected.members)
      }
    })
  }

  it('reaches every code of the taxonomy', () => {
    const reached = new Set<string>()
    for (const leaf of leaves) {
      const got = verdictOf(archiveBytes(leaf), expectation(leaf).caps)
      if (got.verdict === 'reject') reached.add(got.code)
    }
    expect(CODES.filter((code) => !reached.has(code))).toEqual([])
  })

  it('carries the same code list and the same messages as the corpus table', () => {
    const table = codesTable()
    expect([...CODES]).toEqual(table.codes)
    expect(MESSAGES).toEqual(table.messages)
  })
})
