# Security Policy

attest is the durable, portable, user-held layer of possession for digital content: a buyer holds
a signed purchase receipt and anyone can verify it offline, long after the store is gone. A flaw
in verification, canonicalization, or key handling can let a forged or revoked receipt pass as
valid. Please treat security issues with care.

## Supported versions

Both published specification versions receive security fixes. This is not a
courtesy: a receipt is meant to outlive the store that issued it, so a signature
profile stops being supported only if it is broken, never because it is old.

| Version | Supported | Status |
|---------|-----------|--------|
| 0.2     | ✅        | Published on PyPI and npm. Hybrid Ed25519 + ML-DSA-65 profile, Stage 2 transparency and anchoring evidence, Stage 3 issuer-mediated transfer, Stage 4 preservation pledge, time-boxed key compromise, publisher authority |
| 0.1     | ✅        | Published on PyPI and npm. v0.1 receipts remain verifiable indefinitely — always readable, not always valid: an issuer's later compromise declaration for a key still invalidates the receipts signed with that key that were not logged and anchored before it |

This table names signature profiles, not package releases: the current package
version is whatever `attest-receipts` and `attest-verifier` show on their
registries. Please report against a commit or a package version you can name,
rather than against a number written here.

Report anything affecting either profile, including the post-quantum half of the
hybrid profile.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Report it privately
by email to `bernalli@proton.me`.

Please include:

- the affected component (spec section, reference implementation, or the TypeScript verifier) and version/commit;
- a description of the issue and its security impact (e.g. signature bypass, fail-open, canonicalization mismatch, revocation bypass);
- a minimal reproduction — ideally a conformance-style vector (envelope + trust store + expected vs. actual `VerificationResult`).

## What to expect

- Acknowledgement of your report within 5 business days.
- A private assessment and, if confirmed, a coordinated fix before public disclosure.
- Credit for the discovery in the release notes, unless you ask to remain anonymous.

Please give us a reasonable window to ship a fix before any public disclosure.
No public zero-day disclosures.
