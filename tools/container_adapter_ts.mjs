#!/usr/bin/env node
// The TypeScript container reader, behind a line protocol.
//
// Reads one JSON request per line on stdin — {"path": …, "caps": {maxEntries,
// maxMemberBytes, maxTotalBytes}} — and prints one JSON verdict per line, in
// the same shape `tools/container_differential.py` computes from the Python
// reader. The differential runner is what turns "both implementations agree"
// from a claim into a measurement.
//
// The bundle to import is built by the runner (esbuild, into a temp dir) and
// passed as argv[2]; run standalone with a path to a prebuilt bundle.

import { createInterface } from 'node:readline'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const bundlePath = process.argv[2]
if (!bundlePath) {
  process.stderr.write('usage: container_adapter_ts.mjs <bundle.mjs>\n')
  process.exit(2)
}

const { canonicalMembers, readMember, ReadBudget, ContainerError } = await import(
  pathToFileURL(bundlePath).href
)

function verdict(bytes, caps) {
  try {
    const members = canonicalMembers(bytes, caps)
    const budget = new ReadBudget(caps.maxMemberBytes, caps.maxTotalBytes)
    const read = members.map((member) => {
      const data = readMember(bytes, member, budget)
      return {
        name: member.name,
        method: member.method,
        size: data.length,
        sha256: createHash('sha256').update(data).digest('hex'),
      }
    })
    return { verdict: 'accept', members: read }
  } catch (error) {
    if (error instanceof ContainerError) {
      return { verdict: 'reject', code: error.code, member: error.member }
    }
    // Anything else is a defect in the reader, not a verdict about the file:
    // report it as such rather than letting it look like a refusal.
    return { verdict: 'crash', error: String((error && error.message) || error) }
  }
}

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })
for await (const line of lines) {
  const trimmed = line.trim()
  if (!trimmed) continue
  const request = JSON.parse(trimmed)
  const bytes = new Uint8Array(readFileSync(request.path))
  process.stdout.write(JSON.stringify(verdict(bytes, request.caps)) + '\n')
}
