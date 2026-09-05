/**
 * The recorded result of the inherited-copy audit (plan step 5b, procedure (b)).
 * Machine-readable so that the suite can re-decide it; the human-readable table in
 * `desktop/README.md` is pinned against this file by `inherited-copy.test.ts`.
 */

export const G1_SENTENCE = 'can fetch the manifest over TLS'

export type AuditVerdict = 'TRUE' | 'FALSE' | 'NOT-A-TOOL-CLAIM'

export interface AuditRow {
  module: string
  /** SHA-256 (hex) of the exact string literal, as `enumerateInheritedCopy` computes it. */
  sha256: string
  /** Enough of the sentence for a person to find it. */
  excerpt: string
  /** Which token of the closed list put it in scope. */
  token: string
  /** The tool the sentence makes a claim about, or why it makes none. */
  claimAbout: string
  /** The command that DECIDES the claim. Not a citation: a command. */
  command: string
  verdict: AuditVerdict
  /** When the command above was last run. */
  audited: string
}

export const AUDITED_COPY: readonly AuditRow[] = [
  {
    module: 'render',
    sha256: '2eaf85fcf652aa21db20235522114f94987d1364c651c29d7547b7d3390db999',
    excerpt: 'This page did not check this bundle — it is larger than this page will read, ',
    token: 'will ',
    claimAbout:
      "None, and deliberately: v0.1 §14.4 wants this refusal to assert nothing about the bytes, so the sentence names a PROPERTY — a verifier with different limits — and never a product. An earlier draft ended 'Try the attest CLI, which reads more', which is FALSE on the axis this change introduced: the reference importer bounds the container as stored at 1 GiB and this page bounds nothing there, so above that bound the CLI reads LESS. What the sentence does state is this page's own limit, which this page itself enforces.",
    command:
      "cd site && npx vitest run test/render.test.ts test/bundle.test.ts  # the branch is reachable only through BundleTooLargeError, and the assertions pin the neutral register; grep -n 'maxEntries\\|maxTotalBytes' src/container.ts shows the limit the sentence refers to is this page's own",
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-03',
  },
  {
    module: 'render',
    sha256: 'f2b76be9cde727516c43399c6760469421a5e712a32ad97d29dce105e7795d69',
    excerpt: '… — and could not. Why, this run cannot say.',
    token: 'run ',
    claimAbout:
      'Nothing. It is a REFUSAL to claim: the confinement probe reaches this branch only when the browser recorded no policy violation for its own request, and the probe URL is under a reserved TLD that never resolves, so the failure is not attributable to any policy.',
    command:
      'cd site && npx vitest run test/probe.test.ts test/render-demo.test.ts  # the sentence and its neutral tone are reachable only with observed === false; the good tone and "refused it under this page’s own policy" require a securitypolicyviolation whose blockedURI is this request’s',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-02',
  },
  {
    module: 'explain',
    sha256: 'ec6dff7daa4e6d7135b2a1f3410af9686886b8337979dd2f53ec96c5f2475f32',
    excerpt: 'What cannot be settled from the receipt alone: … This page consults no live feed and is not handed grant or authorization documents',
    token: 'can ',
    claimAbout: 'This artifact. It claims the page consults no live feed.',
    command: 'grep -rn \'fetch(\' site/src/{b64u,bundle,explain,intake,render,run,trusted-log}.ts desktop/src/  # no match; plus the e2e request collector of R1(a)',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: 'e569f4fd1a22095354c32b3411b5e407b41745d867db305a163abd71c9732d09',
    excerpt: '… an ANCHORED time on the Transparency row … can spare a receipt whose signing key its issuer later declared compromised (spec §19)',
    token: 'can ',
    claimAbout: 'This verifier. It claims the anchored-time rescue of spec §19 is implemented.',
    command: 'grep -c ANCHORED_BEFORE_PREFIX verifiers/ts/src/verify.ts  # 5; ls docs/spec/vectors | grep compromise  # 2 vector groups, exercised by site/test/conformance.test.ts',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '9df901bfe9468361b7d441e018e86968148525a409401ac0a0c956c99c1f15f0',
    excerpt: '… so other tools will read this receipt the same way this one does (spec §11 step 5)',
    token: 'will ',
    claimAbout: 'Other attest implementations. It claims schema conformance is interoperable.',
    command: 'cd site && npm test -- conformance  # 241 tests over the shared vector corpus both implementations read',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '03d55d1d667209c777ed48ccfaf653a564ce8ca302dd438f9f50e669795f1fae',
    excerpt: '… The spec reserves a stronger level, “verified”, for keys fetched over TLS …; no attest tool published today performs that fetch',
    token: 'can ',
    claimAbout: 'EVERY attest tool. A negative claim — this is the row gate G1 watches, corrected upstream before this branch was rebased onto it.',
    command: 'grep -rn _PROVENANCE_TLS src/attest/  # 3 hits: one declaration, two comparisons, no assignment. grep -rnE \'requests|httpx|urllib|urlopen|XMLHttpRequest|node-fetch|axios\' src/ verifiers/ts/src/  # no match: neither implementation contains an HTTP client',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '553654b481a99870066b002bc12f61d5f8f09c0f67b320da8ecfe0adfce3b5d9',
    excerpt: 'The CLI can check a feed when one is available.',
    token: 'can ',
    claimAbout: 'The attest CLI, revocation feed.',
    command: 'grep -c \'"--revocations"\' src/attest/cli.py  # 1, on the verify subparser',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '86f3e45a2b1dad4ec22a6fd377b54002918ba20ea0b3ccf7fb598674d07af1eb',
    excerpt: 'The CLI does that evaluation — attest verify --grant-view — and this page does not (spec §18.5)',
    token: 'CLI',
    claimAbout: 'The attest CLI, preservation-pledge evaluation, naming the flag.',
    command: 'grep -n \'"--grant-view"\' src/attest/cli.py  # declared on the verify subparser (line 3447)',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '3701f7a60a486e5ca1638e32fac25634fec4266c291de83887dbc4bd53e056ca',
    excerpt: 'A pledge is in force, it covers this purchase, and it has not opened … Dormant is what a healthy promise looks like',
    token: 'use the',
    claimAbout: 'None. In scope only because “beca(use the) spec states it plainly” contains a token; it describes a result value, not a tool.',
    command: 'n/a — no capability asserted',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '75fc8b1347203ef93a5a6f638b632b368cb0182f420d0344decf520f82b8ec26',
    excerpt: '… The CLI can do that evaluation when its caller supplies that evidence; this page does not.',
    token: 'can ',
    claimAbout: 'The attest CLI, publisher-authorization evaluation.',
    command: 'grep -c \'"--authority-view"\' src/attest/cli.py  # 2 (verify subparser + reader)',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: 'aa8c24989ad6668c363125253e070e68ee4be2ab610412220d50cdd0fafc740c',
    excerpt: 'The publisher’s own signed authorization manifest lists this seller … later conforming documents cannot take away coverage',
    token: 'can ',
    claimAbout: 'None. Describes what a result value means under spec §20.2/§20.4.',
    command: 'n/a — no capability asserted',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '32fff489aec170b5b2f08a2d6c4e18f564cf08721347e632f35c47d19633e832',
    excerpt: 'Sold by a seller whose publisher claim is NOT attested … anyone able to feed junk into this channel can buy exactly the doubt that already existed',
    token: 'can ',
    claimAbout: 'None. States a protocol property (doubt, never denial), not a tool capability.',
    command: 'n/a — no capability asserted',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: 'ae28331bda0e5e464031f33ac502062d61bc19a25667a798563e2ec0187d762b',
    excerpt: 'The publisher’s key material was fetched over TLS … applied here to whoever signed the authorization (spec §20.4, §7.4)',
    token: 'available',
    claimAbout: 'None. Describes what the value means when it occurs; it is not a remedy the reader is told to pursue, and the row is drawn only when the value occurs.',
    command: 'n/a — no capability asserted',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: 'e5d00b3b600cb88cb5d94d9d9ae5a205ba8b66e204d4939aa8c2492b81acfcc0',
    excerpt: 'The publisher’s key material was fetched over TLS … applied here to whoever signed the pledge (spec §18.5, §7.4)',
    token: 'available',
    claimAbout: 'None. Same shape as the row above: the meaning of a value, not a capability.',
    command: 'n/a — no capability asserted',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '8e48c1483abae3ed099575f9a9b8b18f77159c0207945e432ef966ed046cfaa6',
    excerpt: '… the CLI can present a key-manifest claim when an issuer publishes one (spec §10.4)',
    token: 'can ',
    claimAbout: 'The attest CLI, transparency claim of type key-manifest.',
    command: 'grep -c _CLAIM_TYPE_KEY_MANIFEST src/attest/verify.py  # 5; grep -n \'"--transparency"\' src/attest/cli.py  # the flag that carries the claim',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '6cf050693acf890a632c6134fd9fa715a715e64b6fa53802739d2d0fbd50098c',
    excerpt: 'Stronger than logged: the checkpoint covering this entry is anchored in a Bitcoin block header this page pins … no later rewriting can move it',
    token: 'can ',
    claimAbout: 'None. States what an anchor means; the pinning it refers to is this artifact\'s own compiled-in policy.',
    command: 'n/a — no capability asserted',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '548ea8e801e8333df1dcc89b9ff9410d41de69aaecda4f397f95c8f081e45ac2',
    excerpt: 'This key was declared compromised by its issuer … nothing here can tell, so the verifier fails closed (spec v0.1 §7.3, v0.2 §19)',
    token: 'can ',
    claimAbout: 'This verifier. It claims the compromise path fails closed rather than passing.',
    command: 'ls docs/spec/vectors | grep compromise  # 2 vector groups asserting the closed outcome, run by site/test/conformance.test.ts',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'intake',
    sha256: '64278c3086b13982e43cd1dec4fd83af6e25441ab1c4b3998e4f03365ff45737',
    excerpt: '… the file itself is bearer proof: anyone who holds it can produce this',
    token: 'can ',
    claimAbout: 'None. States a property of the file format, not something a tool does.',
    command: 'n/a — no capability asserted',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-05',
  },
  {
    module: 'render',
    sha256: '49e795697b5a31e360df6b3293ef3b14f9709ed3876044b7848ba2a4330dc4c9',
    excerpt: '… it was never examined. Try the attest CLI, or a copy of this page',
    token: 'CLI',
    claimAbout: 'The attest CLI: that it exists and verifies receipts.',
    command: 'grep -c \'add_parser("verify"\' src/attest/cli.py  # 1',
    verdict: 'TRUE',
    audited: '2026-09-01',
  },
  {
    module: 'explain',
    sha256: '885480988eb302bc518c34e027742c181f2ccced664fc643701eb75ec7aa0e35',
    excerpt:
      'The issuer’s key manifest was fetched over TLS from the issuer’s own domain — the strongest provenance attest v0.1 defines (spec §7.4)',
    token: 'fetch',
    claimAbout:
      'None. It states what `trust: "verified"` MEANS when it occurs, and this app cannot reach that value: the three provenance paths it can produce are bundle, embedded and user-supplied — never tls. Same shape as the two `available` rows above.',
    command:
      'cd desktop && npx vitest run provenance-characterization  # 4 tests, one per reachable provenance path, each pinning the verdict short of green',
    verdict: 'NOT-A-TOOL-CLAIM',
    audited: '2026-09-01',
  },
]
