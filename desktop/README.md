# attest desktop verifier

attest is proof of purchase you hold: the seller signs a receipt, you keep the file, and it
verifies offline after the store is gone. This is that verifier as a single HTML file.

One HTML file that checks an attest receipt. No install, no account, no network.

Double click it and your browser opens it. Drop a `.attest` file on it and it tells you
what the file proves and — as plainly as it can — what it does not. Everything happens
on the page: the verifier cannot make a network request while it works, and that is
enforced by the file's own content security policy and proven by tests that fail if any
request leaves the page.

The artifact is `dist/attest-verifier.html`. It is built, never committed.

## Build it yourself

```
cd verifiers/ts && npm ci && npm run build   # the verifier this file embeds
cd ../../desktop && npm ci && npm run build  # produces dist/attest-verifier.html
```

`npm run build` typechecks, bundles, and then inlines the bundle into a single document:
one `<script>`, one `<style>`, no external references at all. The build refuses to write
the file unless every tag, every attribute and every link in the document — wherever it
occurs — is one an explicit allowlist names; there is exactly one outbound link, to the
project site. It also refuses a content security policy whose hashes do not match the
bytes it pins, and any request-making API in the output.

Two consecutive builds produce a byte-identical file. That is a property the build owes
you, and the suite checks it.

## The local-only proof, and how to re-run it

Four independent layers, so that one blind spot does not become the product's blind spot:

1. **Every scenario asserts it.** The end-to-end suite watches every request the page
   makes and fails if a single one has a scheme other than `file:`. It also fails if a
   WebSocket is ever opened. This runs for every scenario — valid receipt, invalid
   receipt, refusal, manifest handover — not just a happy path.
2. **The document forbids it.** The artifact's content security policy is
   `connect-src 'none'`, so even code that is never exercised cannot reach the network.
3. **DNS is taken away underneath it.** The Chromium run launches with
   `--host-resolver-rules=MAP * ~NOTFOUND` and asserts that the page makes exactly one
   request in total: the file itself.
4. **The bytes are scanned.** The built HTML is searched for the APIs that could make a
   request at all. The scanner has a negative self-test: a planted token must make it
   fail, so a scanner that has quietly stopped matching cannot pass silently.

```
cd desktop && npm test                                        # unit and integration
npx playwright install --with-deps chromium firefox webkit
npm run e2e                                                   # the four layers above
```

## How it is distributed, honestly

The file is published as a release asset with its SHA-256 beside it. A document is not
an executable: double-clicking it opens the browser you already have, so there is no
"unidentified developer" dialog on macOS and no "Windows protected your PC" screen —
those gates judge executables. What you may still see is a **download-time** warning from
the browser about an uncommon file type. That is the price of shipping a document
instead of an installer, and we would rather pay it than ask you to click through a
malware warning to check a receipt.

Check what you downloaded:

```
sha256sum attest-verifier.html      # Linux
shasum -a 256 attest-verifier.html  # macOS
certutil -hashfile attest-verifier.html SHA256   # Windows
```

Compare it with the checksum published beside the file. Today that checksum is the hash
of the file we published; it is not yet one you can independently reproduce by building,
because cross-machine reproducibility has not been measured. When it has, this paragraph
changes.

**A lookalike is this file's real risk.** Nothing stops anyone from writing an HTML page
that looks like this one and always says "verifies". There is no code signature on a
document to tell them apart. The checksum, checked against the project's own site, is
the only defence a document can carry — which is why the artifact prints where it came
from and how to check it, in its own footer.

## Why there is no code signing and no file association

**No code signing**: there is nothing to sign. A signed executable would mean shipping a
native app — Electron or Tauri — which would multiply a three-dependency supply chain by
orders of magnitude and put a network-capable runtime under the app's control, turning
"cannot make a request" from a property a test can pin into a claim about configuration.

**No file association, deliberately**: `name.attest` (shareable) and
`name.private.attest` (bearer — never share it) have the same extension as far as macOS
and Windows are concerned, because only the last dot counts. Registering the type would
give the never-share file the icon and the double-click behaviour of the safe one. The
app compensates where it can: it refuses a file named `*.private.attest`, refuses a
bundle that carries salts, and warns when a receipt still carries its delivery salt.

## A copy of this file ages, and that costs you something

The verifier's pinned configuration — the transparency log keys and the anchor policy —
is compiled in and never updates. There is deliberately no auto-update, because a
local-only verifier that phones home is not local-only.

The consequence is specific: an old copy can report a receipt as NOT verifying that a
current copy accepts, because the rescue path for a compromised key needs an anchor your
copy does not know about. The footer's version string is the handle. **Before you trust
a red verdict from a copy you have had for a while, check the project site for a newer
file.** A green or amber verdict does not have this problem.

## Inherited copy, audited

Almost every sentence this artifact shows comes from the shared verifier catalogue, which
it imports whole and renders in full. That is on purpose — one catalogue, one voice — but
it has a consequence a web page does not have: **a sentence frozen into a downloaded file
is wrong for ever**, on every copy.

So the inherited copy is audited rather than assumed. Every user-facing string in the
modules this artifact inlines (`b64u`, `bundle`, `explain`, `intake`, `render`, `run`,
`trusted-log`) is collected mechanically — every string containing one of the closed
token list `can fetch`, `can be`, `can `, `CLI`, `will `, `is able`, `supports`,
`use the`, `run `, `available`, `fetch` — and each one is decided by a **command**, not by
reading. A sentence outside that list is out of scope by construction rather than by
judgement.

`id` is the first 12 hex of the SHA-256 of the exact string, so a sentence that is
**reworded** upstream is caught as surely as one that is added. Both make
`test/inherited-copy.test.ts` fail until the new wording is audited and recorded here.
A row that reads FALSE blocks the build: it is corrected at its source, never filtered
inside this package, because that would leave the site and this file saying two
different things about the project's own level of trust.

| id | module | token | sentence (excerpt) | claim about | deciding command | verdict | audited |
|---|---|---|---|---|---|---|---|
| `ec6dff7daa4e` | `explain.ts` | `can ` | What cannot be settled from the receipt alone: … This page consults no live feed and is not handed grant or authorization documents | This artifact. It claims the page consults no live feed. | `grep -rn 'fetch(' site/src/{b64u,bundle,explain,intake,render,run,trusted-log}.ts desktop/src/  # no match; plus the e2e request collector of R1(a)` | **TRUE** | 2026-09-01 |
| `e569f4fd1a22` | `explain.ts` | `can ` | … an ANCHORED time on the Transparency row … can spare a receipt whose signing key its issuer later declared compromised (spec §19) | This verifier. It claims the anchored-time rescue of spec §19 is implemented. | `grep -c ANCHORED_BEFORE_PREFIX verifiers/ts/src/verify.ts  # 5; ls docs/spec/vectors \| grep compromise  # 2 vector groups, exercised by site/test/conformance.test.ts` | **TRUE** | 2026-09-01 |
| `9df901bfe946` | `explain.ts` | `will ` | … so other tools will read this receipt the same way this one does (spec §11 step 5) | Other attest implementations. It claims schema conformance is interoperable. | `cd site && npm test -- conformance  # 241 tests over the shared vector corpus both implementations read` | **TRUE** | 2026-09-01 |
| `03d55d1d6672` | `explain.ts` | `can ` | … The spec reserves a stronger level, “verified”, for keys fetched over TLS …; no attest tool published today performs that fetch | EVERY attest tool. A negative claim — this is the row gate G1 watches, corrected upstream before this branch was rebased onto it. | `grep -rn _PROVENANCE_TLS src/attest/  # 3 hits: one declaration, two comparisons, no assignment. grep -rnE 'requests\|httpx\|urllib\|urlopen\|XMLHttpRequest\|node-fetch\|axios' src/ verifiers/ts/src/  # no match: neither implementation contains an HTTP client` | **TRUE** | 2026-09-01 |
| `553654b481a9` | `explain.ts` | `can ` | The CLI can check a feed when one is available. | The attest CLI, revocation feed. | `grep -c '"--revocations"' src/attest/cli.py  # 1, on the verify subparser` | **TRUE** | 2026-09-01 |
| `86f3e45a2b1d` | `explain.ts` | `CLI` | The CLI does that evaluation — attest verify --grant-view — and this page does not (spec §18.5) | The attest CLI, preservation-pledge evaluation, naming the flag. | `grep -n '"--grant-view"' src/attest/cli.py  # declared on the verify subparser (line 3447)` | **TRUE** | 2026-09-01 |
| `3701f7a60a48` | `explain.ts` | `use the` | A pledge is in force, it covers this purchase, and it has not opened … Dormant is what a healthy promise looks like | None. In scope only because “beca(use the) spec states it plainly” contains a token; it describes a result value, not a tool. | `n/a — no capability asserted` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `75fc8b134720` | `explain.ts` | `can ` | … The CLI can do that evaluation when its caller supplies that evidence; this page does not. | The attest CLI, publisher-authorization evaluation. | `grep -c '"--authority-view"' src/attest/cli.py  # 2 (verify subparser + reader)` | **TRUE** | 2026-09-01 |
| `aa8c24989ad6` | `explain.ts` | `can ` | The publisher’s own signed authorization manifest lists this seller … later conforming documents cannot take away coverage | None. Describes what a result value means under spec §20.2/§20.4. | `n/a — no capability asserted` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `32fff489aec1` | `explain.ts` | `can ` | Sold by a seller whose publisher claim is NOT attested … anyone able to feed junk into this channel can buy exactly the doubt that already existed | None. States a protocol property (doubt, never denial), not a tool capability. | `n/a — no capability asserted` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `ae28331bda0e` | `explain.ts` | `available` | The publisher’s key material was fetched over TLS … applied here to whoever signed the authorization (spec §20.4, §7.4) | None. Describes what the value means when it occurs; it is not a remedy the reader is told to pursue, and the row is drawn only when the value occurs. | `n/a — no capability asserted` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `e5d00b3b600c` | `explain.ts` | `available` | The publisher’s key material was fetched over TLS … applied here to whoever signed the pledge (spec §18.5, §7.4) | None. Same shape as the row above: the meaning of a value, not a capability. | `n/a — no capability asserted` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `8e48c1483aba` | `explain.ts` | `can ` | … the CLI can present a key-manifest claim when an issuer publishes one (spec §10.4) | The attest CLI, transparency claim of type key-manifest. | `grep -c _CLAIM_TYPE_KEY_MANIFEST src/attest/verify.py  # 5; grep -n '"--transparency"' src/attest/cli.py  # the flag that carries the claim` | **TRUE** | 2026-09-01 |
| `6cf050693acf` | `explain.ts` | `can ` | Stronger than logged: the checkpoint covering this entry is anchored in a Bitcoin block header this page pins … no later rewriting can move it | None. States what an anchor means; the pinning it refers to is this artifact's own compiled-in policy. | `n/a — no capability asserted` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `548ea8e801e8` | `explain.ts` | `can ` | This key was declared compromised by its issuer … nothing here can tell, so the verifier fails closed (spec v0.1 §7.3, v0.2 §19) | This verifier. It claims the compromise path fails closed rather than passing. | `ls docs/spec/vectors \| grep compromise  # 2 vector groups asserting the closed outcome, run by site/test/conformance.test.ts` | **TRUE** | 2026-09-01 |
| `e54412ea9a54` | `intake.ts` | `can ` | … the file itself is bearer proof: anyone who holds it can claim this | None. States a property of the file format, not something a tool does. | `n/a — no capability asserted` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `49e795697b5a` | `render.ts` | `CLI` | … it was never examined. Try the attest CLI, or a copy of this page | The attest CLI: that it exists and verifies receipts. | `grep -c 'add_parser("verify"' src/attest/cli.py  # 1` | **TRUE** | 2026-09-01 |
| `885480988eb3` | `explain.ts` | `fetch` | The issuer’s key manifest was fetched over TLS from the issuer’s own domain — the strongest provenance attest v0.1 defines (spec §7.4) | None. It states what `trust: "verified"` means when it occurs, and this app cannot reach that value: the three provenance paths it can produce are bundle, embedded and user-supplied — never tls. | `cd desktop && npx vitest run provenance-characterization  # 4 tests, one per reachable provenance path` | **NOT-A-TOOL-CLAIM** | 2026-09-01 |
| `f2b76be9cde7` | `render.ts` | `run ` | … — and could not. Why, this run cannot say. | Nothing. It is a REFUSAL to claim: the confinement probe reaches this branch only when the browser recorded no policy violation for its own request, and the probe URL is under a reserved TLD that never resolves, so the failure is not attributable to any policy. | `cd site && npx vitest run test/probe.test.ts test/render-demo.test.ts  # the sentence and its neutral tone are reachable only with observed === false` | **NOT-A-TOOL-CLAIM** | 2026-09-02 |
| `2eaf85fcf652` | `render.ts` | `will ` | This page did not check this bundle — it is larger than this page will read, … | None, and deliberately: §14.4 wants this refusal to assert nothing about the bytes, so the sentence names a property — a verifier with different limits — and never a product. An earlier draft said to try the CLI "which reads more", false on the stored-size axis this change introduced. What it states is this page's own limit, which this page enforces. | `cd site && npx vitest run test/render.test.ts test/bundle.test.ts  # the branch is reachable only through BundleTooLargeError` | **NOT-A-TOOL-CLAIM** | 2026-09-03 |

Result of the audit run on 2026-09-01: 8 NOT-A-TOOL-CLAIM, 10 TRUE. One row was added on 2026-09-02, when the site gained a confinement probe whose report has to distinguish a block the browser witnessed from a request that merely failed: 9 NOT-A-TOOL-CLAIM, 10 TRUE. No row reads FALSE, so the build is not blocked.

## Manual QA before release

Run on a real macOS machine and a real Windows machine, from a real download. These
cannot be measured from CI, and the release is not announced until they pass:

- [ ] Download `attest-verifier.html` through the browser; note any download warning.
- [ ] Double click it from the downloads folder; the default browser opens it.
- [ ] No OS security dialog appears (no Gatekeeper prompt, no SmartScreen screen).
- [ ] The failure banner is NOT visible and the dropzone is enabled.
- [ ] Drag `demo.attest` onto it; an amber verdict appears with its rows.
- [ ] Rename a copy to `demo.private.attest` and drag it; it is refused by name.
- [ ] The footer shows a version string and the checksum instructions.
- [ ] Verify the file's SHA-256 matches the published one.
