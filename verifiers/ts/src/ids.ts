// Identifier shapes shared across the package. Deliberately a leaf module: it
// imports nothing, so any call site can take it without risking an import
// cycle.

/** A receipt id is a 26-character Crockford-base32 ULID.
 *
 * The pattern is normative (`attest-receipt.schema.json`), and it is a
 * PRECONDITION for authentication, not a cosmetic check: a revocation record
 * the issuer signed but left malformed must not authenticate, or it feeds the
 * freshness anchor a statement about a receipt it does not name.
 *
 * Python declares this in `revocation.py`, `transfer.py`, `bundle.py` and
 * `cli.py`; the TypeScript tree declared it twice and the revocation path
 * imported neither copy. One definition, imported — never a third copy. */
export const RECEIPT_ID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/
