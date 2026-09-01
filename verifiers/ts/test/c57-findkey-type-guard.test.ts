import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { loadsStrict, canonicalBytes, JsonObject } from '../src/canon.js'
import { b64uEncode } from '../src/b64u.js'
import { findKey, duplicateKids, verifyKeyManifest } from '../src/manifests.js'

// C-57: a key is never resolved from a manifest by a kid that is not a string.
//
// Python puts this guard at the root, inside `find_key`, so every caller
// inherits it. TypeScript put it in each caller instead, and a list of
// callers is only ever shown to be incomplete when somebody finds the
// missing one — which is how the same property escaped the duplicate-kid guard
// in the first place. `duplicateKids` compares strings only, so an entry keyed
// by the integer 5 is invisible to it; and the kid inside a signature block is
// not covered by any signature, because `signableManifestBytes` drops
// `manifest_signature`. Nothing else refuses the type.
//
// The per-caller checks stay where they are: this removes the OBLIGATION on
// whoever adds the next caller, not the belt already fastened on the ones
// that exist today.

const ISSUER = 'store.example.com'
const SEED = Uint8Array.from({ length: 32 }, () => 57)
const PUB = ed25519.getPublicKey(SEED)
const STRING_KID = `${ISSUER}/keys/test#ed25519-a`

const parse = (value: unknown): JsonObject =>
  loadsStrict(new TextEncoder().encode(JSON.stringify(value))) as JsonObject

// Every JSON-representable non-string. A float cannot reach these paths: the
// attest-JCS profile refuses to serialize one, so the manifest never signs.
const NON_STRING_KIDS: unknown[] = [5, null, true, ['a'], { k: 'v' }]

function manifestKeyedBy(kid: unknown): JsonObject {
  const body = {
    issuer: ISSUER,
    manifest_version: 1,
    issued_at: '2026-06-01T00:00:00Z',
    keys: [
      { kid, pub: b64uEncode(PUB), valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' },
    ],
  }
  const sig = ed25519.sign(canonicalBytes(parse(body)), SEED)
  return parse({ ...body, manifest_signature: { kid, sig: b64uEncode(sig) } })
}

describe('C-57: findKey refuses a non-string kid at the root', () => {
  it('resolves an honest string kid, so every refusal below is about the type', () => {
    const manifest = manifestKeyedBy(STRING_KID)

    expect(findKey(manifest, STRING_KID)).not.toBeNull()
    expect(verifyKeyManifest(manifest)).toBe(true)
  })

  it.each(NON_STRING_KIDS.map((kid) => [typeof kid === 'object' ? JSON.stringify(kid) : String(kid), kid] as const))(
    'resolves nothing for a kid that is %s',
    (_label, kid) => {
      const manifest = manifestKeyedBy(kid)

      // Look the kid up by the value the ENTRY actually carries after the
      // admission boundary, not by the JS literal that built it. The boundary
      // renders integers as bigint, so passing the `number` 5 misses a `5n`
      // entry and the lookup fails for the representation rather than for the
      // type — a defence by accident, which is what this test must not mistake
      // for the guard. Objects and arrays would likewise miss by identity.
      const entry = (manifest['keys'] as JsonObject[])[0]!
      expect(entry['kid']).not.toBe(undefined)
      expect(findKey(manifest, entry['kid'] as unknown as string)).toBeNull()
    },
  )

  it('is the only guard that can see these entries: duplicateKids cannot', () => {
    // Why the fix belongs in findKey and not in the ambiguity guard: two
    // entries sharing an integer kid are not a duplicate to `duplicateKids`,
    // which only ever compares strings.
    const entry = { kid: 5, pub: b64uEncode(PUB), valid_from: '2026-01-01T00:00:00Z', valid_to: null, status: 'active' }

    expect(duplicateKids(parse([entry, entry]) as unknown as unknown[])).toEqual([])
  })
})
