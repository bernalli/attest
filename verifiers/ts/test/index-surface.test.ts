/**
 * What the package exports, pinned by NAME.
 *
 * Two halves, and the second is the one that earns the file. The first says
 * the door is complete: a consumer who has to build trust material from bytes
 * can reach every name that job needs. The second says the door is CLOSED:
 * `storeData`, `manifestData`, the `…Data` twins of the internal modules and
 * `classifyRevocation` all take the snapshot's internal trees, and a single
 * line re-exporting one of them would hand a caller back the very tree the
 * boundary exists to keep — the C-216 family, which this project has already
 * paid for once.
 *
 * Pinned as a LIST and never as a count: a total next to an enumeration is the
 * copy that goes stale first, and a count cannot say WHICH name appeared.
 *
 * This file also does duty as one half of the module-cycle check (plan 5.6b):
 * it imports `../src/index.js` FIRST, while `trust-material-parse.test.ts`
 * imports `../src/manifests.js` first. vitest isolates files, so the two
 * initialisation orders are both exercised — `manifests.ts` imports
 * `trustMaterial.ts` for a value, and if `trustMaterial.ts` ever imported one
 * back, one of the two orders would see a partially initialised module.
 */
import { describe, it, expect } from 'vitest'
import * as index from '../src/index.js'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

const SRC = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'src')

/**
 * Every runtime export of the package, sorted. Adding a name here is a
 * deliberate act: it is the public surface of a published package, and the
 * five trust-material names at the end of it are what F6 added.
 */
const PUBLIC_SURFACE = [
  'ATTEST_VERSION',
  'AUTHORITY_AUTHORIZED',
  'AUTHORITY_NOT_CHECKED',
  'AUTHORITY_NO_CLAIM',
  'AUTHORITY_SELF',
  'AUTHORITY_TRUST_SIGNER_MISMATCH',
  'AUTHORITY_UNATTESTED',
  'AUTHORITY_UNAUTHORIZED',
  'AnchorError',
  'CANONICAL_EMPTY_POLICY_BYTES',
  'CORROBORATION_LOGGED',
  'CORROBORATION_NONE',
  'CORROBORATION_WITNESSED',
  'CanonError',
  'END_OF_LIFE_SUNSET_GRANT',
  'GRANT_ACTIVATED',
  'GRANT_DORMANT',
  'GRANT_INVALID_IGNORED',
  'GRANT_NONE',
  'GRANT_NOT_CHECKED',
  'GRANT_TRUST_NOT_CHECKED',
  'GRANT_TRUST_SIGNER_MISMATCH',
  'GRANT_TRUST_TOFU',
  'GRANT_TRUST_UNVERIFIED_ROTATION',
  'GRANT_TRUST_VERIFIED',
  'KNOWN_PLEDGE_TYPES',
  'KeyManifest',
  'LABEL_REDEMPTION_CHALLENGE',
  'LABEL_TRANSFER_AUTHORIZATION',
  'MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE',
  'MAX_AUTHORITY_DOCUMENTS',
  'MAX_AUTHORIZED_ISSUERS',
  'MAX_GRANT_DECLARATIONS',
  'MAX_GRANT_LATER_VERSIONS',
  'MAX_REVOCATION_RECORDS',
  'MAX_WITNESS_ANCHOR_DELAY_SECONDS',
  'MAX_WITNESS_SKEW_SECONDS',
  'MODE_FIXED_DATE',
  'MODE_HEARTBEAT_ABSENCE',
  'MODE_PUBLISHER_DECLARATION',
  'PERMISSION_DELEGATE',
  'PERMISSION_DELIVER_TO_HOLDER',
  'PERMISSION_ISSUE',
  'PERMISSION_REDISTRIBUTE_AMONG_HOLDERS',
  'PLEDGE_SUNSET_GRANT_V1',
  'ROLE_CORROBORATION',
  'ROLE_SUNSET_ACTIVATION',
  'SIGNER_ROLE_PUBLISHER',
  'SIGNER_ROLE_SUCCESSOR',
  'SUPPORTED_ATTEST_VERSIONS',
  'TRANSPARENCY_EQUIVOCATION_DETECTED',
  'TRANSPARENCY_LOGGED',
  'TRANSPARENCY_NOT_CHECKED',
  'TlogError',
  'TransparencyError',
  'TrustMaterialError',
  'TrustStore',
  'WITNESS_POLICY_SCHEMA_ID',
  'WITNESS_PQ_COSIGNATURE_SIG_TYPE',
  'WitnessError',
  'auditChain',
  'authorizationHash',
  'authorizationMessage',
  'canonicalBytes',
  'declarationCoversGrant',
  'declarationHash',
  'declarationSignerRole',
  'encodeEntry',
  'entryAuthorizesReceipt',
  'entryForIssuer',
  'evaluateActivationWitnessQuorum',
  'evaluateAuthority',
  'evaluateGrant',
  'evaluateTransparency',
  'findWitnessEpoch',
  'grantCoversReceipt',
  'grantHash',
  'isAuthorizationVersion',
  'isNonNarrowing',
  'isOk',
  'leafHash',
  'loadWitnessPolicy',
  'loadsStrict',
  'nodeHash',
  'parseCheckpoint',
  'parseKeyManifest',
  'parseTrustStore',
  'parseWitnessPolicy',
  'passesHorizon',
  'proseDiffers',
  'receiptCoreHash',
  'recordLoggedStanding',
  'redemptionMessage',
  'sameInstant',
  'sha256Hex',
  'signerDomain',
  'transferRecordHash',
  'verify',
  'verifyAnchor',
  'verifyAuthorization',
  'verifyCheckpoint',
  'verifyConsistency',
  'verifyDeclaration',
  'verifyDeclarationSignature',
  'verifyGrant',
  'verifyGrantSignature',
  'verifyInclusion',
  'verifyPublisherAuthorization',
  'verifyPublisherAuthorizationSignature',
  'verifyRedemption',
  'verifySeededAnchor',
  'verifyTransferRecord',
  'verifyTransferRecordSignature',
  'windowSpentAt',
  'withinStructuralCeiling',
  'withinStructuralCeilings',
  'witnessEpochCovers',
  'witnessIsConflicted',
  'witnessPinCovers',
  'witnessPinHasStandingAt',
]

describe('the published surface', () => {
  it('exports exactly the pinned list of names', () => {
    expect(Object.keys(index).sort()).toEqual(PUBLIC_SURFACE)
  })

  it('gives a consumer everything needed to build trust material from bytes', () => {
    // Not implied by the list above: this states WHY those five names are on
    // it, so removing one breaks a test that says what was lost.
    expect(typeof index.parseTrustStore).toBe('function')
    expect(typeof index.parseKeyManifest).toBe('function')
    expect(typeof index.TrustStore).toBe('function')
    expect(typeof index.KeyManifest).toBe('function')
    expect(index.TrustMaterialError.prototype).toBeInstanceOf(Error)
  })

  it('never exports a name that hands back the snapshot internals', () => {
    // Derived from the structure, not from a list written beside it: any name
    // ending in `Data` is a twin that takes an internal tree, so a new one
    // added tomorrow is covered without anyone remembering this test.
    const exported = Object.keys(index)
    const named = ['storeData', 'manifestData', 'classifyRevocation', 'readsAsOwnData']
    for (const forbidden of named) expect(exported).not.toContain(forbidden)
    expect(exported.filter((n) => /Data$/.test(n))).toEqual([])
    expect(exported.filter((n) => /^materialize/.test(n))).toEqual([])
  })
})

describe('who may build a trust-material handle', () => {
  /**
   * The custody check, by AST rather than by counting occurrences of a string.
   *
   * A count pins nothing: it is blind to a construction with different
   * arguments, to an alias bound to a variable, and to `Reflect.construct`.
   * The question asked here is the one that matters — is there, anywhere in
   * `src/`, a place that builds one of these two classes OUTSIDE the file that
   * owns the admission token?
   */
  const constructionSites = (file: string): string[] => {
    const source = ts.createSourceFile(
      file,
      readFileSync(join(SRC, file), 'utf-8'),
      ts.ScriptTarget.ESNext,
      true,
    )
    const found: string[] = []
    const walk = (node: ts.Node): void => {
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
        const name = node.expression.text
        if (name === 'TrustStore' || name === 'KeyManifest') found.push(name)
      }
      // `Reflect.construct(TrustStore, …)` reaches the constructor without a
      // `new`, so an AST walk that only looked at NewExpression would miss it.
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        node.expression.expression.text === 'Reflect' &&
        node.expression.name.text === 'construct'
      ) {
        found.push('Reflect.construct')
      }
      ts.forEachChild(node, walk)
    }
    walk(source)
    return found
  }

  it('builds them only inside trustMaterial.ts', () => {
    const others = readdirSync(SRC).filter((f) => f.endsWith('.ts') && f !== 'trustMaterial.ts')
    // The negative that makes this test non-decorative: if the walk found
    // nothing anywhere, an empty result would look like success. So assert the
    // owning file DOES construct them, first.
    expect(constructionSites('trustMaterial.ts').length).toBeGreaterThan(0)
    for (const file of others) {
      expect(constructionSites(file), `${file} must not construct trust material`).toEqual([])
    }
  })

  it('refuses a caller who writes the constructor', () => {
    // The type system says a caller can write it; the runtime says no. Both
    // halves matter: a private constructor in the type system alone is erased
    // at compile time and stops nobody who runs plain JavaScript.
    expect(() => new (index.TrustStore as unknown as new () => unknown)()).toThrow(TypeError)
    expect(() => new (index.KeyManifest as unknown as new () => unknown)()).toThrow(TypeError)
  })
})
