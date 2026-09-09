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
    // The two classes, and every LOCAL NAME bound to them in this file.
    // Matching the identifier TEXT alone was blind to the very forms the
    // comment above says a count misses: `import { TrustStore as TS }` and
    // `const C = TrustStore` both reach the constructor under a name that is
    // not the class's own. Measured 2026-09-08: text matching caught 3 of 8
    // real construction forms.
    const CLASSES: ReadonlySet<string> = new Set(['TrustStore', 'KeyManifest'])
    const bound = new Set<string>(CLASSES)
    const namespaces = new Set<string>()
    const collect = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node) && node.importClause) {
        const named = node.importClause.namedBindings
        if (named && ts.isNamedImports(named)) {
          for (const el of named.elements) {
            if (CLASSES.has((el.propertyName ?? el.name).text)) bound.add(el.name.text)
          }
        }
        if (named && ts.isNamespaceImport(named)) namespaces.add(named.name.text)
      }
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer &&
        ts.isIdentifier(node.initializer) &&
        bound.has(node.initializer.text)
      ) {
        bound.add(node.name.text)
      }
      ts.forEachChild(node, collect)
    }
    collect(source)

    /** The class a construction target names, under any spelling, or null. */
    const handleName = (n: ts.Expression): string | null => {
      if (ts.isIdentifier(n)) return bound.has(n.text) ? n.text : null
      if (
        ts.isPropertyAccessExpression(n) &&
        ts.isIdentifier(n.expression) &&
        namespaces.has(n.expression.text) &&
        CLASSES.has(n.name.text)
      ) {
        return n.name.text
      }
      return null
    }

    const found: string[] = []
    const walk = (node: ts.Node): void => {
      if (ts.isNewExpression(node)) {
        const name = handleName(node.expression)
        if (name !== null) found.push(name)
      }
      // `class X extends TrustStore` reaches the constructor through `super()`.
      if ((ts.isClassDeclaration(node) || ts.isClassExpression(node)) && node.heritageClauses) {
        for (const clause of node.heritageClauses) {
          if (clause.token !== ts.SyntaxKind.ExtendsKeyword) continue
          for (const t of clause.types) {
            const name = handleName(t.expression)
            if (name !== null) found.push(`extends ${name}`)
          }
        }
      }
      // `Reflect.construct(TrustStore, ...)` reaches the constructor without a
      // `new`. Flagged unconditionally, and the BINDING form too: `const rc =
      // Reflect.construct` hides the call site from a property-access match.
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        node.expression.expression.text === 'Reflect' &&
        node.expression.name.text === 'construct'
      ) {
        found.push('Reflect.construct')
      }
      if (
        ts.isVariableDeclaration(node) &&
        node.initializer &&
        ts.isPropertyAccessExpression(node.initializer) &&
        ts.isIdentifier(node.initializer.expression) &&
        node.initializer.expression.text === 'Reflect' &&
        node.initializer.name.text === 'construct'
      ) {
        found.push('Reflect.construct')
      }
      ts.forEachChild(node, walk)
    }
    walk(source)
    return found
  }

  it('builds them only inside trustMaterial.ts', () => {
    // `recursive: true`: a no-op today (src/ is flat, measured 20 files either
    // way) and the difference between a guard that derives its watched set from
    // the structure and one that silently stops covering a subdirectory added
    // tomorrow.
    const others = readdirSync(SRC, { recursive: true })
      .map((f) => String(f))
      .filter((f) => f.endsWith('.ts') && f !== 'trustMaterial.ts')
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
