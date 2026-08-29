"""RFC 6962 Merkle tree verification primitives and closed transparency-log
entry schemas — Stage 2 (design §2.1.1/§2.1.2).

Scope: this module is the foundation every later Stage-2 task builds on. It
provides:

- Leaf/interior node hashing (`leaf_hash`, `node_hash`) per RFC 6962 §2.1.
- Verification of an inclusion proof (`verify_inclusion`, §2.1.1) and a
  consistency proof (`verify_consistency`, §2.1.2) against an untrusted
  proof list — both fail closed on any malformed input, never raise.
- Builder-side tree construction (`build_tree`, `inclusion_proof`,
  `consistency_proof`) used by `gen_vectors` and the CLI to produce the
  proofs the verify functions above consume. These operate on trusted,
  well-formed input and raise `ValueError` on invalid arguments (index out
  of range, unsorted sizes) rather than failing closed — there is no
  untrusted-input boundary here.
- `encode_entry`, which validates a log entry against the two CLOSED entry
  schemas below and returns its canonical (attest-JCS) bytes — the exact
  bytes that get leaf-hashed into the log.
- Hybrid signed-note checkpoints (`Checkpoint`, `LogKey`, `parse_checkpoint`,
  `verify_checkpoint`, `sign_checkpoint`) — C2SP tlog-checkpoint style notes
  carrying BOTH an Ed25519 and an ML-DSA-65 signature. Standing requires
  BOTH to verify (fail-closed AND) and the checkpoint's origin to match a
  pinned expectation — mirrors `manifests.py`'s hybrid `manifest_signature`
  discipline (design doc "checkpoint auth is hybrid, mandatory").

Verification here NEVER trusts caller-declared shapes: proof elements are
type/length-checked before use, and comparisons use `hmac.compare_digest`
throughout (constant-time; malformed proofs are not a valid channel to leak
timing on legitimate log state).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Final

from attest import canon, keys, pq

_HASH_LEN = 32  # SHA-256 digest length in bytes
_MAX_JCS_INTEGER = 2**53 - 1
_LEAF_PREFIX = b"\x00"  # RFC 6962 §2.1: MTH({d(0)}) = SHA-256(0x00 || d(0))
_NODE_PREFIX = b"\x01"  # RFC 6962 §2.1: MTH(D[n]) = SHA-256(0x01 || left || right)

_TYPE_KEY_MANIFEST = "key-manifest"
_TYPE_RECEIPT = "receipt"
_TYPE_REVOCATION_RECORD = "revocation-record"
_TYPE_TRANSFER_RECORD = "transfer-record"
_TYPE_CESSATION_DECLARATION = "cessation-declaration"
_TYPE_PUBLISHER_AUTHORIZATION = "publisher-authorization"
_KEY_MANIFEST_FIELDS = frozenset({"type", "issuer", "manifest_version", "manifest_sha256"})
_RECEIPT_FIELDS = frozenset({"type", "issuer", "core_sha256"})
_REVOCATION_RECORD_FIELDS = frozenset({"type", "issuer", "record_sha256"})
_TRANSFER_RECORD_FIELDS = frozenset({"type", "issuer", "record_sha256"})
_CESSATION_DECLARATION_FIELDS = frozenset({"type", "issuer", "record_sha256"})
_PUBLISHER_AUTHORIZATION_FIELDS = frozenset({"type", "issuer", "record_sha256"})

# Same lowercase-DNS shape as the receipt schema's `issuer.id` pattern
# (src/attest/schema/attest-receipt.schema.json) — kept in sync by hand,
# this module has no schema-file dependency.
_ISSUER_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class TlogError(ValueError):
    """A transparency-log artifact does not conform to its required format."""


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 §2.1 leaf hash: `SHA-256(0x00 || data)`."""
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1 interior node hash: `SHA-256(0x01 || left || right)`."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than `n` (RFC 6962 calls this `k`).

    Callers only invoke this for `n >= 2`, where the result is always well
    defined (`k` in `[1, n)`).
    """
    k = 1
    while k * 2 < n:
        k *= 2
    return k


# --------------------------------------------------------------------------
# Builder side: construction (trusted input, O(n log n)).
# --------------------------------------------------------------------------


def build_tree(leaves: list[bytes]) -> bytes:
    """RFC 6962 §2.1 Merkle Tree Hash (MTH) of `leaves`.

    `MTH({}) = SHA-256()` (hash of the empty string — no leaf prefix byte;
    this is the sole exception to the leaf/node hashing scheme, defined
    directly by RFC 6962 §2.1). `MTH({d0}) = leaf_hash(d0)`. For `n > 1`,
    split at `k = largest power of two < n` and combine the two subtree
    roots with `node_hash`.
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_power_of_two_below(n)
    return node_hash(build_tree(leaves[:k]), build_tree(leaves[k:]))


def _path(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 §2.1.1 `PATH(m, D[n])`, ordered leaf-adjacent-first.

    `PATH(m, {d0}) = {}`. For `n > 1`, split at `k`; if `m < k` recurse into
    the left subtree and append the right subtree's root, else recurse into
    the right subtree (re-based index `m - k`) and append the left
    subtree's root. Recursion runs before the append, so the proof is
    built bottom (near the leaf) to top (near the root) — the order
    `verify_inclusion` expects.
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if m < k:
        return [*_path(leaves[:k], m), build_tree(leaves[k:])]
    return [*_path(leaves[k:], m - k), build_tree(leaves[:k])]


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Build the RFC 6962 §2.1.1 audit path for `leaves[index]`."""
    n = len(leaves)
    if not isinstance(index, int) or index < 0 or index >= n:
        raise ValueError(f"index {index!r} out of range for {n} leaves")
    return _path(leaves, index)


def _subproof(leaves: list[bytes], m: int, b: bool) -> list[bytes]:
    """RFC 6962 §2.1.2 `SUBPROOF(m, D[n], b)`.

    `b` is true only on the initial call: once the recursion has taken the
    "right subtree" branch, the boundary between old/new tree no longer
    passes through the root of what remains, so the base case must emit an
    explicit subtree hash instead of an empty proof.
    """
    n = len(leaves)
    if m == n:
        return [] if b else [build_tree(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return [*_subproof(leaves[:k], m, b), build_tree(leaves[k:])]
    return [*_subproof(leaves[k:], m - k, False), build_tree(leaves[:k])]


def consistency_proof(leaves: list[bytes], size1: int) -> list[bytes]:
    """Build the RFC 6962 §2.1.2 consistency proof between the size-`size1`
    prefix of `leaves` and `leaves` itself (size `len(leaves)`).

    `size1 == 0` (consistency against the empty tree) is vacuous — RFC 6962
    defines no proof in that case, so this returns `[]` directly rather
    than recursing (the general `SUBPROOF` recursion is only defined for
    `1 <= m <= n`).
    """
    n = len(leaves)
    if not isinstance(size1, int) or size1 < 0 or size1 > n:
        raise ValueError(f"size1={size1!r} out of range for {n} leaves")
    if size1 == 0:
        return []
    return _subproof(leaves, size1, True)


# --------------------------------------------------------------------------
# Verification side: untrusted proof input, fail-closed, never raises.
# --------------------------------------------------------------------------


def _valid_proof_shape(proof: object) -> bool:
    return isinstance(proof, list) and all(
        isinstance(p, bytes) and len(p) == _HASH_LEN for p in proof
    )


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes
) -> bool:
    """RFC 6962 §2.1.1 inclusion proof verification, iterative.

    Fail-closed: any malformed argument (wrong types, out-of-range index,
    wrongly-shaped proof elements, too-short/too-long proof) returns
    `False` rather than raising — `leaf`/`index`/`proof`/`root` all arrive
    from an untrusted log server.
    """
    if (
        not isinstance(leaf, bytes)
        or len(leaf) != _HASH_LEN
        or not isinstance(root, bytes)
        or len(root) != _HASH_LEN
    ):
        return False
    if not isinstance(index, int) or isinstance(index, bool):
        return False
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        return False
    if index < 0 or tree_size <= 0 or index >= tree_size:
        return False
    if not _valid_proof_shape(proof):
        return False

    fn, sn = index, tree_size - 1
    computed = leaf
    for sibling in proof:
        if sn == 0:
            return False  # proof has more elements than the path to the root
        if fn % 2 == 1 or fn == sn:
            computed = node_hash(sibling, computed)
            # `fn` was the lone (unpaired) rightmost node at this level: climb
            # without consuming further proof elements until it either
            # becomes a right child (a real sibling exists) or reaches root.
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            computed = node_hash(computed, sibling)
        fn //= 2
        sn //= 2
    return sn == 0 and hmac.compare_digest(computed, root)


def verify_consistency(
    size1: int, root1: bytes, size2: int, root2: bytes, proof: list[bytes]
) -> bool:
    """RFC 6962 §2.1.2 consistency proof verification, iterative.

    Fail-closed: any malformed argument returns `False` rather than
    raising.
    """
    if not isinstance(size1, int) or isinstance(size1, bool):
        return False
    if not isinstance(size2, int) or isinstance(size2, bool):
        return False
    if (
        not isinstance(root1, bytes)
        or len(root1) != _HASH_LEN
        or not isinstance(root2, bytes)
        or len(root2) != _HASH_LEN
    ):
        return False
    if size1 < 0 or size2 < 0 or size1 > size2:
        return False
    if not _valid_proof_shape(proof):
        return False

    if size1 == size2:
        return len(proof) == 0 and hmac.compare_digest(root1, root2)
    if size1 == 0:
        return len(proof) == 0

    node, last_node = size1 - 1, size2 - 1
    idx = 0
    n_proof = len(proof)

    while node % 2 == 1:
        node //= 2
        last_node //= 2

    if node > 0:
        if idx >= n_proof:
            return False
        new_hash = proof[idx]
        old_hash = proof[idx]
        idx += 1
    else:
        new_hash = root1
        old_hash = root1

    while node > 0:
        if node % 2 == 1:
            if idx >= n_proof:
                return False
            sibling = proof[idx]
            idx += 1
            new_hash = node_hash(sibling, new_hash)
            old_hash = node_hash(sibling, old_hash)
        elif node < last_node:
            if idx >= n_proof:
                return False
            sibling = proof[idx]
            idx += 1
            new_hash = node_hash(new_hash, sibling)
        node //= 2
        last_node //= 2

    if not hmac.compare_digest(old_hash, root1):
        return False

    while last_node > 0:
        if idx >= n_proof:
            return False
        sibling = proof[idx]
        idx += 1
        new_hash = node_hash(new_hash, sibling)
        last_node //= 2

    if idx != n_proof:
        return False  # unconsumed proof elements

    return hmac.compare_digest(new_hash, root2)


# --------------------------------------------------------------------------
# Closed log-entry schemas.
# --------------------------------------------------------------------------


def _require_fields(entry: dict[str, Any], expected: frozenset[str]) -> None:
    if any(not isinstance(key, str) for key in entry):
        raise TlogError("entry field names must be strings")
    actual = frozenset(entry.keys())
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise TlogError(f"entry field mismatch: missing={missing} extra={extra}")


def _require_entry_scalar_bounds(entry: dict[str, Any]) -> None:
    """Bound field names and string values before rendering, regexes, or JCS."""
    for field, value in entry.items():
        if (isinstance(field, str) and len(field) > _MAX_ENTRY_SCALAR_LEN) or (
            isinstance(value, str) and len(value) > _MAX_ENTRY_SCALAR_LEN
        ):
            raise TlogError(f"entry scalar exceeds {_MAX_ENTRY_SCALAR_LEN} chars")


def _require_issuer(entry: dict[str, Any]) -> None:
    issuer = entry.get("issuer")
    if not isinstance(issuer, str) or not _ISSUER_RE.fullmatch(issuer):
        raise TlogError(f"issuer must be a lowercase DNS name: {issuer!r}")


def _require_hex64(entry: dict[str, Any], field: str) -> None:
    value = entry.get(field)
    if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
        raise TlogError(f"{field} must be 64 lowercase hex characters: {value!r}")


def _require_manifest_version(entry: dict[str, Any]) -> None:
    version = entry.get("manifest_version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or not 1 <= version <= _MAX_JCS_INTEGER
    ):
        raise TlogError(f"manifest_version must be an int in [1, {_MAX_JCS_INTEGER}]: {version!r}")


def encode_entry(entry: dict[str, Any]) -> bytes:
    """Validate `entry` against a CLOSED schema and return its canonical
    (attest-JCS) bytes — the exact bytes that get leaf-hashed into the log.

    Exactly six entry types, exactly these members each (extras rejected):

    - `key-manifest`: `{"type", "issuer", "manifest_version", "manifest_sha256"}`,
      where `manifest_sha256 = SHA-256(JCS(manifest))` (lowercase hex).
    - `receipt`: `{"type", "issuer", "core_sha256"}`, where `core_sha256` is
      the Task 5 signed-receipt-core hash (lowercase hex). `issuer` here is
      a NON-authenticated hint only — a convenience for log browsing/
      filtering, never a trust anchor; the receipt's own signature is what
      binds it to an issuer.
    - `revocation-record` (v0.2 §8, G5): `{"type", "issuer", "record_sha256"}`,
      where `record_sha256 = attest.revocation.record_hash(record)` —
      `SHA-256(JCS(record))` over the ENTIRE signed revocation record
      (including its own `signature` member), the same canonical form
      `revocation.py` already builds and verifies the record's signature
      over. `issuer` here is the same NON-authenticated browsing hint as
      `receipt`'s — the record's own signature is what binds it to an
      issuer, checked by `revocation.verify_record`, never by this entry.
    - `transfer-record` (v0.2 §8/§17.1, Stage 3): `{"type", "issuer",
      "record_sha256"}`, where `record_sha256 = attest.transfer.record_hash(record)` —
      `SHA-256(JCS(record))` over the ENTIRE signed transfer record
      (including its own `signature` member), the same canonical form
      `transfer.py` already builds and verifies the record's signature over.
      `issuer` here is the same NON-authenticated browsing hint as the other
      entry types' — the record's own signature is what binds it to an
      issuer, checked by `transfer.verify_record`, never by this entry.
    - `cessation-declaration` (v0.2 §8/§18.4, Stage 4): `{"type", "issuer",
      "record_sha256"}`, where `record_sha256 = attest.grant.declaration_hash(
      declaration)` — `SHA-256(JCS(declaration))` over the ENTIRE signed
      cessation declaration (including its own `signature` member), the same
      canonical form `grant.py` already builds and verifies the declaration's
      signature over. `issuer` here is the same NON-authenticated browsing
      hint as the other entry types' — the declaration's own signature
      (verified against the publisher's key manifest, v0.2 §18.1) is what
      binds it, never this entry. Unlike `transfer-record`, this entry type is
      NOT load-bearing: §18.4 RECOMMENDS logging a declaration, for
      discoverability and for a date opposable to third parties, but a
      declaration that authenticates activates a grant whether or not it was
      ever logged.
    - `publisher-authorization` (v0.2 §8/§20.2): `{"type", "issuer",
      "record_sha256"}`, where `record_sha256 = attest.authority.authorization_hash(
      document)` — `SHA-256(JCS(document))` over the ENTIRE signed publisher
      authorization manifest (including its own `signature` member), the same
      canonical form `authority.py` already builds and verifies the document's
      signature over. `issuer` here is the PUBLISHER's domain and remains the
      same NON-authenticated browsing hint as the other entry types' — the
      document's own signature (verified against the publisher's key manifest,
      v0.2 §18.1/§20.2) is what binds it, never this entry. Like
      `cessation-declaration` and unlike `transfer-record`, this entry type is
      NOT load-bearing: §20.2 RECOMMENDS logging, and an authenticated
      authorization binds whether or not it was ever logged — currency
      disputes are resolved by `authorization_version`, not by the log.

    Raises `TlogError` on an unknown `type`, a missing/extra member, or a
    member with the wrong value shape.
    """
    if not isinstance(entry, dict):
        raise TlogError(f"entry must be an object, got {type(entry).__name__}")

    _require_entry_scalar_bounds(entry)
    entry_type = entry.get("type")
    if entry_type == _TYPE_KEY_MANIFEST:
        _require_fields(entry, _KEY_MANIFEST_FIELDS)
        _require_issuer(entry)
        _require_manifest_version(entry)
        _require_hex64(entry, "manifest_sha256")
    elif entry_type == _TYPE_RECEIPT:
        _require_fields(entry, _RECEIPT_FIELDS)
        _require_issuer(entry)
        _require_hex64(entry, "core_sha256")
    elif entry_type == _TYPE_REVOCATION_RECORD:
        _require_fields(entry, _REVOCATION_RECORD_FIELDS)
        _require_issuer(entry)
        _require_hex64(entry, "record_sha256")
    elif entry_type == _TYPE_TRANSFER_RECORD:
        _require_fields(entry, _TRANSFER_RECORD_FIELDS)
        _require_issuer(entry)
        _require_hex64(entry, "record_sha256")
    elif entry_type == _TYPE_CESSATION_DECLARATION:
        _require_fields(entry, _CESSATION_DECLARATION_FIELDS)
        _require_issuer(entry)
        _require_hex64(entry, "record_sha256")
    elif entry_type == _TYPE_PUBLISHER_AUTHORIZATION:
        _require_fields(entry, _PUBLISHER_AUTHORIZATION_FIELDS)
        _require_issuer(entry)
        _require_hex64(entry, "record_sha256")
    else:
        raise TlogError(f"unknown entry type: {entry_type!r}")

    return canon.dumps(entry).encode("utf-8")


# Domain-separated signed-receipt-core hash prefix (design doc fix 4) — the
# ONLY receipt-entry hash domain; see `receipt_core_hash`.
_RECEIPT_CORE_DOMAIN = b"attest-receipt-core-v1\x00"


def receipt_core_hash(envelope: dict[str, Any]) -> str:
    """Domain-separated signed-receipt-core hash (design doc fix 4) — the
    ONLY receipt-entry hash domain: `SHA-256("attest-receipt-core-v1\\x00" ||
    JCS(payload) || 0x00 || JCS(signatures))`, where `signatures` is
    `envelope["signatures"]` canonicalized as a JSON array. `delivery` is
    deliberately excluded — deleting it never invalidates a receipt's log
    entry.

    Committing to the SIGNATURE BYTES (not just `payload`) is deliberate,
    not redundant: post-CRQC, an attacker who has derived an issuer's
    Ed25519 private key from its public key can sign a backdated payload
    at will. A hash over `payload` alone would let a pre-committed log
    entry describe a payload that was never actually signed until long
    after it was logged — the attacker signs it later, past the horizon,
    and the old entry still "matches" the forged receipt. Hashing the
    signature bytes too means the entry can only ever describe a signature
    that already existed at logging time (design vector 28l's property: an
    unsigned payload-only precommit is NOT accepted as receipt existence
    proof).

    `envelope` must carry object member `payload` and array member
    `signatures` — the same shape `verify()` step 0 already parses. Raises
    `TlogError` if either is missing or wrong-shaped: this is trusted-input
    builder-side surface, like this module's other construction functions
    (`build_tree`, `inclusion_proof`, ...), not a fail-closed boundary over
    untrusted data.
    """
    if not isinstance(envelope, dict):
        raise TlogError(f"envelope must be an object, got {type(envelope).__name__}")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise TlogError("envelope missing object member 'payload'")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list):
        raise TlogError("envelope missing array member 'signatures'")
    digest = hashlib.sha256(
        _RECEIPT_CORE_DOMAIN
        + canon.dumps(payload).encode("utf-8")
        + b"\x00"
        + canon.dumps(signatures).encode("utf-8")
    ).digest()
    return digest.hex()


# --------------------------------------------------------------------------
# Hybrid signed-note checkpoints (C2SP tlog-checkpoint profile, hybrid AND).
# --------------------------------------------------------------------------

# C2SP signed-note signature line: em dash U+2014, one space, name, one
# space, standard base64 (with padding) of the signature blob. Name grammar
# is checked separately so its C2SP printable-ASCII rules are shared by
# parsing, verification, and signing.
_SIG_LINE_RE = re.compile(r"\A— ([^ ]+) ([A-Za-z0-9+/]+={0,2})\Z")
# Strict ASCII decimal only: `str.isdigit()` also accepts non-decimal
# Unicode digit-value characters (e.g. superscript "²") that `int()` then
# rejects, which would leak a bare (non-TlogError) ValueError.
_DECIMAL_RE = re.compile(r"\A[0-9]+\Z")
_KEY_HASH_LEN = 4  # C2SP signed-note key-hash prefix length, bytes
_ED25519_PUB_LEN = 32
_ED25519_SIG_LEN = 64
# C2SP signed-note type byte 0x01 identifies Ed25519. ML-DSA-65 has no
# assigned identifier byte, so it uses the registry's own extension
# mechanism: 0xff ("signature types without an identifier byte assigned by
# this specification") followed by a longer identifier unlikely to collide.
# Collision-proof by construction — no future single-byte assignment (0x06
# went to ML-DSA-44 cosignatures) can clash with an 0xff-prefixed type.
_ED25519_SIG_TYPE = b"\x01"
_ML_DSA_65_SIG_TYPE = b"\xff" + b"attest-ml-dsa-65"
_MAX_TREE_SIZE = 2**64 - 1
# A uint64 can have at most 20 decimal digits. Capping before `int()` sees it
# avoids both a bare (non-TlogError)
# ValueError from CPython's int-string-conversion digit limit (3.11+,
# default 4300 digits) and the O(n^2) parse cost a huge digit string would
# otherwise incur on untrusted input.
_MAX_TREE_SIZE_DIGITS = 20
# C2SP recommends a signature limit while requiring acceptance of at least
# 16. Sixty-four leaves room for witness cosignatures without unbounded work.
_MAX_NOTE_SIGNATURES = 64
# Worst-case legitimate note is ~400KB: 3 header lines plus 64 ML-DSA-65
# signature lines at ~4.4KB base64 each. This matches anchor.py's
# _MAX_CHECKPOINT_TEXT_LEN rationale, which remains caller-side defense in depth.
_MAX_NOTE_TEXT_LEN = 500_000
_MAX_NOTE_LINES = 4 + _MAX_NOTE_SIGNATURES
# Entry schemas contain only a few short identifiers/hashes.  Keep their
# per-scalar bound aligned with the established signed-note text ceiling so
# either core rejects hostile diagnostic/regex/canonicalization input first.
_MAX_ENTRY_SCALAR_LEN = _MAX_NOTE_TEXT_LEN
# Largest legitimate signature blob is 4 (key hash) + 3309 (ML-DSA-65) =
# 3313 bytes -> 4420 base64 chars; 8192 is generous headroom. Checked
# BEFORE base64-decoding so a hostile line cannot force a large allocation.
_MAX_SIG_B64_LEN = 8192
# A 32-byte root encodes to ceil(32 / 3) * 4 = exactly 44 base64 chars.
# Checked BEFORE base64-decoding so a hostile root cannot force a large allocation.
_MAX_ROOT_B64_LEN = 44


def _trunc_repr(value: str, limit: int = 80) -> str:
    """Bound an untrusted string's ASCII repr for an error message — slice
    BEFORE rendering so a multi-megabyte hostile field is never fully
    rendered (escaped controls and non-ASCII code points amplify output)."""
    if len(value) <= limit:
        return ascii(value)
    return ascii(value[:limit]) + "…"


@dataclass(frozen=True)
class Checkpoint:
    """A parsed C2SP signed-note transparency-log checkpoint body.

    `note_bytes` is exactly the bytes a note signature is computed over:
    the three header lines (origin, tree size, base64 root) through their
    final newline, excluding the blank line separating them from signatures.

    `signed_note_bytes` is the FULL checkpoint text as parsed — the same
    header lines, the blank line, AND every C2SP signature line, byte-for-
    byte the original input to `parse_checkpoint`/`verify_checkpoint`
    (never re-serialized). `anchor.py`'s v2 anchor profile
    (`"signed-note-v2"`, attest-v0.2.md §11.1) commits an OTS op-chain over
    this instead of `note_bytes` alone: `note_bytes` is unsigned-header-only
    text that exists identically before and after the note is actually
    signed, so a v1 (`note_bytes`-only) OTS anchor proves only that SOME
    note with this header existed by a given time, not that anyone had
    signed it yet — the pre-anchor-then-sign gap TM-33's residual risk
    documents. `signed_note_bytes` contains the real signature-line bytes,
    so a v2 anchor cannot exist before the note was actually signed.
    """

    origin: str
    tree_size: int
    root: bytes
    note_bytes: bytes
    signed_note_bytes: bytes


@dataclass(frozen=True)
class LogKey:
    """A pinned transparency-log signing identity: one `name`, two legs.

    Ships baked into the verifier's trust store — never taken from an
    untrusted bundle (design doc "log keys pinned out-of-band").
    """

    origin: str
    name: str
    ed25519_pub: bytes
    mldsa_pub: bytes


def _key_hash(name: str, signature_type: bytes, pub: bytes) -> bytes:
    """C2SP key ID: `SHA-256(name || "\\n" || type || pub)[:4]`."""
    return hashlib.sha256(name.encode() + b"\n" + signature_type + pub).digest()[:_KEY_HASH_LEN]


def _validate_origin(origin: object, field: str = "origin") -> str:
    """Require a non-empty printable-ASCII checkpoint origin.

    C2SP origins are schema-less-URL-style ASCII in practice. Keeping this
    grammar ASCII-only also makes acceptance independent of the host
    runtime's Unicode database.
    """
    if (
        not isinstance(origin, str)
        or not origin
        or any(not "\x20" <= character <= "\x7e" for character in origin)
    ):
        raise TlogError(f"{field} must be a non-empty printable ASCII str")
    return origin


def _validate_key_name(name: object, field: str = "name") -> str:
    """Require a non-empty printable-ASCII C2SP signed-note key name."""
    if (
        not isinstance(name, str)
        or not name
        or "+" in name
        or any(not "\x21" <= character <= "\x7e" for character in name)
    ):
        raise TlogError(f"{field} must be non-empty printable ASCII without '+'")
    return name


def _validate_bytes(value: object, field: str, length: int) -> bytes:
    """Require an exactly-sized byte string without leaking `len()` errors."""
    if not isinstance(value, bytes) or len(value) != length:
        raise TlogError(f"{field} must be {length} bytes")
    return value


def _parse_tree_size(size_str: str) -> int:
    """Parse an ASCII-decimal uint64 tree size without an int-conversion DoS."""
    if not _DECIMAL_RE.fullmatch(size_str):
        raise TlogError(f"tree size must be ASCII decimal digits: {_trunc_repr(size_str)}")
    if len(size_str) > 1 and size_str.startswith("0"):
        raise TlogError(f"tree size must not contain leading zeros: {_trunc_repr(size_str)}")
    if len(size_str) > _MAX_TREE_SIZE_DIGITS:
        raise TlogError(f"tree size has too many digits ({len(size_str)}): {_trunc_repr(size_str)}")
    try:
        tree_size = int(size_str)
    except ValueError as exc:  # defensive: the preceding grammar makes this unreachable
        raise TlogError(f"tree size is not a valid integer: {_trunc_repr(size_str)}") from exc
    if tree_size > _MAX_TREE_SIZE:
        raise TlogError(f"tree size must be a uint64: {_trunc_repr(size_str)}")
    return tree_size


def _note_bytes(header: list[str]) -> bytes:
    """Encode C2SP note text: header lines including, not after, final LF."""
    try:
        return ("\n".join(header) + "\n").encode()
    except UnicodeEncodeError as exc:
        raise TlogError("checkpoint text must be valid UTF-8") from exc


def _validate_log_key(log_key: object) -> LogKey:
    """Validate every pinned-key field before cryptographic verification."""
    if not isinstance(log_key, LogKey):
        raise TlogError("log_key must be a LogKey")
    _validate_origin(log_key.origin, "log_key.origin")
    _validate_key_name(log_key.name, "log_key.name")
    _validate_bytes(log_key.ed25519_pub, "log_key.ed25519_pub", _ED25519_PUB_LEN)
    _validate_bytes(log_key.mldsa_pub, "log_key.mldsa_pub", pq.ML_DSA_65_PK_LEN)
    return log_key


def _validate_signing_keys(signing_keys: object) -> pq.HybridSigningKeys:
    """Validate builder key material so malformed inputs only raise TlogError."""
    if not isinstance(signing_keys, pq.HybridSigningKeys):
        raise TlogError("signing_keys must be HybridSigningKeys")
    if not isinstance(signing_keys.ed, keys.SigningKeyPair):
        raise TlogError("signing_keys.ed must be SigningKeyPair")
    if not isinstance(signing_keys.mldsa, pq.MLDSAKeyPair):
        raise TlogError("signing_keys.mldsa must be MLDSAKeyPair")
    _validate_bytes(signing_keys.ed.seed, "signing_keys.ed.seed", _ED25519_PUB_LEN)
    _validate_bytes(signing_keys.ed.pub, "signing_keys.ed.pub", _ED25519_PUB_LEN)
    _validate_bytes(signing_keys.mldsa.sk, "signing_keys.mldsa.sk", pq.ML_DSA_65_SK_LEN)
    _validate_bytes(signing_keys.mldsa.pub, "signing_keys.mldsa.pub", pq.ML_DSA_65_PK_LEN)
    return signing_keys


def _split_note(text: str) -> tuple[list[str], list[str]]:
    """Split raw checkpoint `text` into its 3 header lines and its signature
    lines, validating the C2SP note shape only (never field contents).

    Raises `TlogError` on: non-str input; missing trailing newline (every
    line, including the last signature line, is `\\n`-terminated — text not
    ending in `\\n` carries trailing garbage); too few lines to hold a
    header plus its blank-line separator; or a missing blank line
    immediately after the 3 header lines.
    """
    if not isinstance(text, str):
        raise TlogError(f"checkpoint text must be a str, got {type(text).__name__}")
    if not text.endswith("\n"):
        raise TlogError("checkpoint text must end with a newline")
    if len(text) > _MAX_NOTE_TEXT_LEN:
        raise TlogError(f"checkpoint text exceeds {_MAX_NOTE_TEXT_LEN} chars")
    if text.count("\n") > _MAX_NOTE_LINES:
        raise TlogError(f"checkpoint text has too many lines (max {_MAX_NOTE_LINES})")
    lines = text.split("\n")[:-1]  # drop the "" produced by the trailing \n
    if len(lines) < 4:
        raise TlogError("checkpoint text is too short for a header plus blank line")
    header, rest = lines[:3], lines[3:]
    if rest[0] != "":
        raise TlogError("checkpoint header must be followed by a blank line")
    return header, rest[1:]


def _parse_signature_lines(lines: list[str]) -> list[tuple[str, bytes]]:
    """Parse each `— <name> <base64(blob)>` line into `(name, blob)`.

    Raises `TlogError` on any line that doesn't match the exact C2SP note
    signature-line shape, or whose blob isn't valid base64 — malformed
    lines are never silently skipped. A well-formed line whose `name` just
    isn't the one the caller wants is NOT filtered here: `verify_checkpoint`
    does that filtering over the parsed `(name, blob)` pairs.
    """
    if not lines:
        raise TlogError("checkpoint must contain at least one signature line")
    if len(lines) > _MAX_NOTE_SIGNATURES:
        raise TlogError(f"checkpoint has too many signature lines (max {_MAX_NOTE_SIGNATURES})")
    parsed = []
    for line in lines:
        m = _SIG_LINE_RE.fullmatch(line)
        if m is None:
            raise TlogError(f"malformed checkpoint signature line: {_trunc_repr(line)}")
        name, blob_b64 = m.group(1), m.group(2)
        _validate_key_name(name, "signature key name")
        if len(blob_b64) > _MAX_SIG_B64_LEN:
            raise TlogError(f"signature blob exceeds {_MAX_SIG_B64_LEN} base64 chars")
        try:
            blob = base64.b64decode(blob_b64, validate=True)
        except ValueError as exc:
            raise TlogError(f"signature blob is not valid base64: {_trunc_repr(blob_b64)}") from exc
        parsed.append((name, blob))
    return parsed


def _parse(text: str) -> tuple[Checkpoint, list[tuple[str, bytes]]]:
    """Shared parse core for `parse_checkpoint`/`verify_checkpoint`: one pass
    over `text` producing both the header `Checkpoint` and the parsed
    signature-line `(name, blob)` pairs, so neither caller re-derives the
    other's half of the note."""
    header, sig_lines = _split_note(text)
    origin, size_str, root_b64 = header
    origin = _validate_origin(origin)
    tree_size = _parse_tree_size(size_str)
    if len(root_b64) > _MAX_ROOT_B64_LEN:
        raise TlogError(f"root exceeds {_MAX_ROOT_B64_LEN} base64 chars")
    try:
        root = base64.b64decode(root_b64, validate=True)
    except ValueError as exc:
        raise TlogError(f"root is not valid base64: {_trunc_repr(root_b64)}") from exc
    if len(root) != _HASH_LEN:
        raise TlogError(f"root must decode to {_HASH_LEN} bytes, got {len(root)}")
    signatures = _parse_signature_lines(sig_lines)
    note_bytes = _note_bytes(header)
    # `text` is NOT pure ASCII (each C2SP signature line opens with the
    # em dash U+2014, a 3-byte UTF-8 sequence) but IS guaranteed valid UTF-8
    # by this point: `_validate_origin`, `_parse_tree_size`, base64 root
    # decoding, and `_parse_signature_lines` (key-name grammar + base64 blob
    # charset) each already constrain their slice of `text` to printable
    # ASCII, and the em dash itself came from this same already-decoded
    # `str`, so `.encode()` can't raise here — this is not a
    # re-serialization, it's the original input bytes back.
    signed_note_bytes = text.encode()
    checkpoint = Checkpoint(
        origin=origin,
        tree_size=tree_size,
        root=root,
        note_bytes=note_bytes,
        signed_note_bytes=signed_note_bytes,
    )
    return checkpoint, signatures


ED25519_SIG_TYPE: Final = _ED25519_SIG_TYPE


def key_hash(name: str, signature_type: bytes, pub: bytes) -> bytes:
    """C2SP key ID: `SHA-256(name || "\\n" || type || pub)[:4]`.

    Public because witness cosignatures (v0.2 §9.2) are a different C2SP
    signature type over the same note, and computing their key ID must use
    this exact construction rather than a second copy of it.
    """
    return _key_hash(name, signature_type, pub)


def note_signatures(text: str) -> list[tuple[str, bytes]]:
    """Parse a signed note's `(name, blob)` signature lines.

    Raises `TlogError` on a malformed note, exactly as `_parse` does — a
    caller holding an already-verified checkpoint cannot hit that path, and
    one that has not verified anything should not be reading signature lines
    as if they meant something.
    """
    _, signatures = _parse(text)
    return signatures


def parse_checkpoint(text: str) -> Checkpoint:
    """Parse a C2SP signed-note checkpoint body: line 1 origin, line 2
    decimal tree size, line 3 base64 std-encoded 32-byte root, a blank
    line, then one or more `— <name> <base64(blob)>` signature lines.

    Structural/shape validation only — no signature is checked here, see
    `verify_checkpoint`. Raises `TlogError` on any malformation: wrong
    header line count, missing blank line, non-decimal tree size, a root
    that isn't 32 bytes once base64-decoded, a malformed signature line,
    missing signatures, invalid C2SP origin/key-name grammar, or a missing
    trailing newline.
    """
    checkpoint, _signatures = _parse(text)
    return checkpoint


def verify_checkpoint(text: str, log_key: LogKey, expected_origin: str) -> Checkpoint:
    """Verify a checkpoint's hybrid signed-note signature and origin binding.

    Fail-closed AND (design doc "checkpoint auth is hybrid, mandatory",
    mirrors `manifests.py`'s `manifest_signature` discipline): standing
    requires BOTH an Ed25519 AND an ML-DSA-65 signature line by
    `log_key.name`, each verifying over `checkpoint.note_bytes` against the
    matching leg's pinned public key, AND `checkpoint.origin` must equal
    both `expected_origin` and `log_key.origin`.

    Each candidate signature line's 4-byte key-hash prefix
    (`SHA-256(name || "\\n" || signature-type || pub)[:4]`) is checked against the expected
    prefix for that leg before its signature is verified — a wrong prefix
    means "signed by a different key" and that line simply doesn't count
    toward either leg; scanning continues over the remaining lines.

    Raises `TlogError` (never returns a bool) on any parse error, origin
    mismatch, or missing/invalid signature leg, each with a message naming
    the failed condition.
    """
    log_key = _validate_log_key(log_key)
    expected_origin = _validate_origin(expected_origin, "expected_origin")

    checkpoint, signatures = _parse(text)
    if checkpoint.origin != expected_origin:
        raise TlogError(
            f"checkpoint origin {checkpoint.origin!r} != expected_origin {expected_origin!r}"
        )
    if checkpoint.origin != log_key.origin:
        raise TlogError(
            f"checkpoint origin {checkpoint.origin!r} != log_key.origin {log_key.origin!r}"
        )

    ed_prefix = _key_hash(log_key.name, _ED25519_SIG_TYPE, log_key.ed25519_pub)
    mldsa_prefix = _key_hash(log_key.name, _ML_DSA_65_SIG_TYPE, log_key.mldsa_pub)
    ed_ok = False
    mldsa_ok = False
    for name, blob in signatures:
        if name != log_key.name:
            continue  # signed-note convention: unknown names are skipped, not fatal
        if len(blob) == _KEY_HASH_LEN + _ED25519_SIG_LEN and blob[:_KEY_HASH_LEN] == ed_prefix:
            if keys.verify_strict(checkpoint.note_bytes, blob[_KEY_HASH_LEN:], log_key.ed25519_pub):
                ed_ok = True
        elif (
            len(blob) == _KEY_HASH_LEN + pq.ML_DSA_65_SIG_LEN
            and blob[:_KEY_HASH_LEN] == mldsa_prefix
        ):
            if pq.verify_strict(checkpoint.note_bytes, blob[_KEY_HASH_LEN:], log_key.mldsa_pub):
                mldsa_ok = True
        if ed_ok and mldsa_ok:
            break

    if not (ed_ok and mldsa_ok):
        raise TlogError(
            f"checkpoint has no valid Ed25519+ML-DSA-65 signature pair for name {log_key.name!r}"
        )
    return checkpoint


def sign_checkpoint(
    origin: str, tree_size: int, root: bytes, signing_keys: pq.HybridSigningKeys, name: str
) -> str:
    """Build and hybrid-sign a C2SP checkpoint note (builder/offline signer).

    Deviates from a flat `(ed25519_seed, mldsa_sk)` parameter pair: computing
    each leg's key-hash prefix needs that leg's PUBLIC key too, and FIPS 204
    doesn't make an ML-DSA public key cheaply recoverable from its secret
    key alone. This takes `pq.HybridSigningKeys` instead — the existing
    bundle type that already carries both legs' `(secret, public)` pairs,
    matching how `manifests.py`'s `_sign_manifest` takes the same type.
    """
    origin = _validate_origin(origin)
    name = _validate_key_name(name)
    root = _validate_bytes(root, "root", _HASH_LEN)
    if (
        not isinstance(tree_size, int)
        or isinstance(tree_size, bool)
        or not 0 <= tree_size <= _MAX_TREE_SIZE
    ):
        raise TlogError(f"tree_size must be a uint64: {tree_size!r}")
    signing_keys = _validate_signing_keys(signing_keys)

    header = [origin, str(tree_size), base64.b64encode(root).decode("ascii")]
    note_bytes = _note_bytes(header)
    ed_blob = _key_hash(name, _ED25519_SIG_TYPE, signing_keys.ed.pub) + keys.sign(
        note_bytes, signing_keys.ed
    )
    mldsa_blob = _key_hash(name, _ML_DSA_65_SIG_TYPE, signing_keys.mldsa.pub) + pq.sign(
        note_bytes, signing_keys.mldsa
    )
    ed_line = f"— {name} {base64.b64encode(ed_blob).decode('ascii')}\n"
    mldsa_line = f"— {name} {base64.b64encode(mldsa_blob).decode('ascii')}\n"
    return note_bytes.decode() + "\n" + ed_line + mldsa_line
