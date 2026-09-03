"""Builders for the side-document VIEWS a verifier consumes, plus a local
diagnostic for one compromise claim (v0.2 §8, §12, §17.1, §19.3).

Every rail `verify()` accepts had consumers and no producer: the revocation
view, the transfer view and the compromise view were assembled by hand in
tests, tools and documentation, which is how a wire format drifts. This module
is the single producer. It builds artifacts and refuses to build malformed
ones; it never classifies a receipt and never decides trust.

Two properties hold everywhere here, and both are load-bearing:

1. **Materialization at the door.** `canon.dumps` walks a mapping with
   `for k in obj` and reads members with `obj[k]`, both shadowable, so
   canonicalizing a caller-supplied object can serialize something other than
   the object's own data (`canon.py:83-106`). Every public function copies each
   argument with `canon.own_data_copy` on first use and reads only the copy
   from then on. No `canon.canonical_bytes` is ever reached by a value that
   was not copied first.
2. **One error type.** A malformed input leaves through `ViewError` and
   nothing else — a builder that let a `KeyError`, a `TypeError` or a
   `TransparencyError` escape would make its callers guess which failures are
   the input's fault.

Ceilings are never restated: `manifests.MAX_MANIFEST_KEYS`,
`revocation.MAX_REVOCATION_RECORDS`, `transfer.MAX_TRANSFER_CLAIMS` and
`verify._MAX_COMPROMISE_CLAIMS` are read from the modules that own them, for
the reason `revocation.py:29-35` already gives: a ceiling restated in two
places is a ceiling that will drift.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from datetime import UTC
from typing import Any

from attest import anchor, canon, manifests, pq, revocation, tlog, transfer, verify

# Predicates and bounds borrowed from sibling modules, most of them private.
# The precedent is `cli.py:107`, which reads
# `verify._MAX_TRANSPARENCY_EVIDENCE_LEN` for exactly this reason: the
# alternative is a second spelling of a rule that already has one. Bound at
# import time so a rename over there breaks HERE, out loud, instead of leaving
# a silently divergent copy behind — which is not a hypothetical: while this
# module was being written `revocation._RECEIPT_ID_RE` was promoted to the
# public `RECEIPT_ID_RE`, and this line is where that surfaced.
# `tests/test_views.py::test_verify_private_predicates_exist` pins the list.
_MAX_COMPROMISE_CLAIMS = verify._MAX_COMPROMISE_CLAIMS
_materialize_compromise_view = verify._materialize_compromise_view
_authenticated_compromise_claims = verify._authenticated_compromise_claims
_cutoff_denying_manifests = verify._cutoff_denying_manifests
_claim_has_cutoff_signer = verify._claim_has_cutoff_signer
_resolve_compromise_cutoff = verify._resolve_compromise_cutoff
_RECEIPT_ID_RE = revocation.RECEIPT_ID_RE
_valid_holder_authorization_shape = transfer._valid_holder_authorization_shape
_strict_b64u_decode = transfer._strict_b64u_decode

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_COMPROMISED = "compromised"
_ED25519_SIG_LEN = 64
_ED25519_PUB_LEN = 32

# An RFC 6962 inclusion proof carries one sibling hash per level, so a tree of
# 2**64 leaves needs at most 64 nodes. Anything longer is not a proof of
# anything a log could have produced, and iterating it unbounded is work an
# untrusted input must not be able to buy.
MAX_INCLUSION_PROOF_NODES = 64

# A SHA-256 Merkle node on the wire: 64 lowercase hex characters. `tlog`
# spells the same shape for entry hashes; this one is about proof nodes, which
# `tlog` never sees.
_HEX64_RE = re.compile(r"[0-9a-f]{64}")

# `attest log prove` emits exactly these five members (`cli.py:2011-2017`);
# `attest log anchor` adds `anchors` and nothing else.
_EVIDENCE_REQUIRED: tuple[str, ...] = (
    "entry",
    "leaf_index",
    "tree_size",
    "inclusion_proof",
    "checkpoint",
)
_EVIDENCE_OPTIONAL: tuple[str, ...] = ("anchors",)

# v0.2 §17.1's closed six-member transfer record (`transfer.py:39-48`).
_TRANSFER_RECORD_MEMBERS: tuple[str, ...] = (
    "receipt_id",
    "new_receipt_id",
    "new_holder_pubkey",
    "transferred_at",
    "holder_authorization",
    "signature",
)

# §8's closed revocation record and §12's status registry. A record is a
# statement about a receipt's standing; `revoked` and `transferred` are the two
# statements that exist, and an unknown third would be silently ignored by
# every verifier that reads the view.
_REVOCATION_RECORD_MEMBERS: tuple[str, ...] = (
    "receipt_id",
    "status",
    "revoked_at",
    "signature",
)
_REVOCATION_STATUSES: frozenset[str] = frozenset({"revoked", "transferred"})

_SIGNATURE_REQUIRED: tuple[str, ...] = ("kid", "sig")
_SIGNATURE_OPTIONAL: tuple[str, ...] = ("sig_ml_dsa_65",)


class ViewError(ValueError):
    """A view or claim could not be built from the material given.

    Always the caller's input, never a verdict about a receipt: this module
    refuses to PRODUCE an artifact it cannot vouch for, and says why.
    """


# --- materialization and shape primitives ------------------------------------


def _own(value: object, what: str) -> Any:
    """`value`'s own data, copied out into exact plain types (regola 0, P32).

    The copy runs before anything else touches the value, and refuses on a node
    budget rather than after the work is already done. Every failure mode of
    `own_data_copy` — budget exhaustion, colliding keys, a container whose
    accessors raise — is the caller's input being unusable, so all of them
    leave as `ViewError`.
    """
    try:
        return canon.own_data_copy(value, [canon.MAX_ADMISSION_NODES])
    # Broad on purpose: budget exhaustion, colliding keys and a container whose
    # own accessors raise are the same fact — the caller's input is unusable.
    except Exception as exc:
        raise ViewError(f"{what} could not be read as its own data: {exc}") from exc


def _own_object(value: object, what: str) -> dict[str, Any]:
    copied = _own(value, what)
    if not isinstance(copied, dict):
        raise ViewError(f"{what} must be an object, got {type(value).__name__}")
    return copied


def _own_list(value: object, what: str) -> list[Any]:
    copied = _own(value, what)
    if not isinstance(copied, list):
        raise ViewError(f"{what} must be an array, got {type(value).__name__}")
    return copied


def _closed_object(
    value: dict[str, Any], required: Sequence[str], optional: Sequence[str], what: str
) -> None:
    """Exactly `required`, optionally `optional`, nothing else.

    Both directions matter: a missing member is a document that does not say
    what it must, and an extra one is a member no verifier reads and no
    signature necessarily covers.
    """
    present = set(value)
    missing = sorted(member for member in required if member not in present)
    if missing:
        raise ViewError(f"{what} is missing required member(s): {missing}")
    extra = sorted(repr(key) for key in present - set(required) - set(optional))
    if extra:
        raise ViewError(f"{what} carries unknown member(s): {extra}")


def _is_int(value: object) -> bool:
    """A genuine integer. `bool` subclasses `int` in Python and a `true` on the
    wire is never a count, a version or an index."""
    return isinstance(value, int) and not isinstance(value, bool)


def _round_trips(value: object) -> bool:
    """The signed UTC wire shape, checked by ROUND TRIP.

    `strptime` alone accepts `2025-8-1T0:0:0Z` (P34), which no conforming
    producer emits and which re-serializes to different bytes; comparing the
    reformatted string against the original is what refuses it.
    """
    if not isinstance(value, str):
        return False
    try:
        return manifests._parse_date(value).strftime(_DATE_FMT) == value
    except (TypeError, ValueError):
        return False


def _canonical(value: object, what: str) -> bytes:
    try:
        return canon.canonical_bytes(value)
    # `CanonError` for a float or an over-deep body, `TypeError` for a key that
    # is not a string: all of them mean the same unshippable artifact.
    except Exception as exc:
        raise ViewError(f"{what} has no canonical form: {exc}") from exc


def _admissible(value: dict[str, Any], what: str, *, nesting: int) -> None:
    """Refuse an artifact the verifier could never admit.

    The boundary is not restated here: `canon.materialize_value` IS the shared
    reconstruction boundary of §18.4. `nesting` is the position the VERIFIER
    reads this rail at, and the two rails differ: a compromise claim is
    materialized at `VIEW_MEMBER_NESTING` (`verify._materialize_compromise_view`),
    a transfer claim and a revocation record at `VIEW_ARRAY_ELEMENT_NESTING`.
    Asking for the deeper position everywhere looks conservative and is not: it
    makes this producer refuse a claim the verifier would have accepted, which
    is a producer/consumer mismatch in the direction nobody notices — the
    artifact simply never gets built. Depth ceiling, code-point ceiling and the
    profile's refusal of floats all come from that one call, which is why none
    of those three numbers appears in this file.
    """
    if canon.materialize_value(value, nesting) is None:
        raise ViewError(
            f"{what} is not admissible: too deeply nested, too large, or carrying a "
            "value outside the attest-JCS profile"
        )


def _validated_entry(entry: dict[str, Any], what: str) -> dict[str, Any]:
    """`entry` iff the log's own closed schema accepts it (`tlog.encode_entry`).

    The entry is COMPUTED here from the document, never read off the evidence,
    so this only catches a document whose own members cannot form a legal entry
    (a non-DNS issuer, a `manifest_version` outside the JCS integer range).
    """
    try:
        tlog.encode_entry(entry)
    except tlog.TlogError as exc:
        raise ViewError(f"{what} cannot form a transparency-log entry: {exc}") from exc
    return entry


def _signature_block_kid(block: object, what: str) -> str:
    """Validate a `{kid, sig, sig_ml_dsa_65?}` block and return its `kid`."""
    if not isinstance(block, dict):
        raise ViewError(f"{what} 'signature' must be an object, got {type(block).__name__}")
    _closed_object(block, _SIGNATURE_REQUIRED, _SIGNATURE_OPTIONAL, f"{what} 'signature'")
    kid = block["kid"]
    if not isinstance(kid, str) or not kid:
        raise ViewError(f"{what} 'signature.kid' must be a non-empty string: {kid!r}")
    if _strict_b64u_decode(block["sig"], _ED25519_SIG_LEN) is None:
        raise ViewError(
            f"{what} 'signature.sig' must be canonical base64url of a "
            f"{_ED25519_SIG_LEN}-byte Ed25519 signature"
        )
    if "sig_ml_dsa_65" in block and (
        _strict_b64u_decode(block["sig_ml_dsa_65"], pq.ML_DSA_65_SIG_LEN) is None
    ):
        raise ViewError(
            f"{what} 'signature.sig_ml_dsa_65' must be canonical base64url of a "
            f"{pq.ML_DSA_65_SIG_LEN}-byte ML-DSA-65 signature"
        )
    return kid


def _issuer_of_kid(kid: str) -> str:
    """The issuer domain a `kid` names: everything before the first `/`.

    Not authenticated by anything here — `tlog.encode_entry` checks it is a
    DNS name, and the document's own signature is what binds it to an issuer.
    """
    return kid.split("/", 1)[0]


def _manifest_key_entries(manifest: dict[str, Any], what: str) -> list[Any]:
    """The manifest's `keys[]`, checked against the §7.1 ceiling BEFORE anything
    canonicalizes it — an oversized array must not be able to buy the work of
    a signature check (same order as `manifests.verify_key_manifest`)."""
    entries = manifest.get("keys")
    if not isinstance(entries, list):
        raise ViewError(f"{what} 'keys' must be an array, got {type(entries).__name__}")
    if len(entries) > manifests.MAX_MANIFEST_KEYS:
        raise ViewError(
            f"{what} exceeds {manifests.MAX_MANIFEST_KEYS} keys: {len(entries)} entries"
        )
    return entries


def _require_evidence_shape(
    evidence: dict[str, Any], expected_entry: dict[str, Any], what: str
) -> None:
    """The `attest log prove` shape (P14), plus the optional `anchors` that
    `attest log anchor` adds.

    `entry` must equal the entry COMPUTED from the document this evidence is
    paired with. That equality is the whole point of §19.3 item 4: an evidence
    bundle proving the inclusion of some OTHER document is the mutation this
    check exists to catch, and reading the hash off the evidence instead would
    make the check vacuous. Nothing cryptographic happens here — verifying the
    proof and the checkpoint is the verifier's job, against ITS pins.
    """
    _closed_object(evidence, _EVIDENCE_REQUIRED, _EVIDENCE_OPTIONAL, what)
    if evidence["entry"] != expected_entry:
        raise ViewError(
            f"{what} 'entry' does not commit to this document: "
            f"expected {expected_entry!r}, got {evidence['entry']!r}"
        )
    leaf_index = evidence["leaf_index"]
    if not _is_int(leaf_index) or leaf_index < 0:
        raise ViewError(f"{what} 'leaf_index' must be a non-negative integer: {leaf_index!r}")
    tree_size = evidence["tree_size"]
    if not _is_int(tree_size) or tree_size <= leaf_index:
        raise ViewError(
            f"{what} 'tree_size' must be an integer greater than 'leaf_index' "
            f"({leaf_index!r}): {tree_size!r}"
        )
    proof = evidence["inclusion_proof"]
    if not isinstance(proof, list):
        raise ViewError(f"{what} 'inclusion_proof' must be an array: {type(proof).__name__}")
    if len(proof) > MAX_INCLUSION_PROOF_NODES:
        raise ViewError(
            f"{what} 'inclusion_proof' exceeds {MAX_INCLUSION_PROOF_NODES} nodes: {len(proof)}"
        )
    for node in proof:
        if not isinstance(node, str) or not _HEX64_RE.fullmatch(node):
            raise ViewError(
                f"{what} 'inclusion_proof' node is not 64 lowercase hex characters: {node!r}"
            )
    if not isinstance(evidence["checkpoint"], str):
        raise ViewError(f"{what} 'checkpoint' must be a string")
    if "anchors" in evidence and not isinstance(evidence["anchors"], dict):
        raise ViewError(f"{what} 'anchors' must be an object when present")


def _deduplicated(built: Iterable[dict[str, Any]], what: str) -> list[dict[str, Any]]:
    """Refuse CANONICALLY IDENTICAL elements and nothing else (F9).

    Two claims about the same subject with different evidence are two different
    facts — one may carry an anchor the other does not — so deduplicating by
    the subject's hash would silently drop the stronger standing. Order is the
    caller's and is never rewritten.
    """
    seen: set[bytes] = set()
    result: list[dict[str, Any]] = []
    for index, element in enumerate(built):
        digest = _canonical(element, f"{what} element {index}")
        if digest in seen:
            raise ViewError(f"{what} element {index} is canonically identical to an earlier one")
        seen.add(digest)
        result.append(element)
    return result


# --- log entries -------------------------------------------------------------


def key_manifest_log_entry(manifest: dict[str, Any]) -> dict[str, Any]:
    """The `key-manifest` transparency-log entry for `manifest` (v0.2 §8).

    `{"type", "issuer", "manifest_version", "manifest_sha256"}` where
    `manifest_sha256 = SHA-256(JCS(manifest))` over the ENTIRE manifest,
    signature member included — the same canonical form `verify.py` recomputes
    when it checks a compromise claim (`verify.py:1131-1138`).
    """
    return _key_manifest_log_entry(_own_object(manifest, "key manifest"))


def _key_manifest_log_entry(own: dict[str, Any]) -> dict[str, Any]:
    """`key_manifest_log_entry` on an ALREADY materialized manifest."""
    _manifest_key_entries(own, "key manifest")
    issuer = own.get("issuer")
    if not isinstance(issuer, str):
        raise ViewError(f"key manifest 'issuer' must be a string, got {type(issuer).__name__}")
    version = own.get("manifest_version")
    if not _is_int(version):
        raise ViewError(f"key manifest 'manifest_version' must be an integer: {version!r}")
    entry = {
        "type": "key-manifest",
        "issuer": issuer,
        "manifest_version": version,
        "manifest_sha256": hashlib.sha256(_canonical(own, "key manifest")).hexdigest(),
    }
    return _validated_entry(entry, "key manifest")


# --- compromise declarations (v0.2 §19.3) ------------------------------------


def build_compromise_claim(manifest: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """One `{manifest, evidence}` compromise claim, or `ViewError`.

    What is checked, in this order: the §7.1 ceiling on `keys[]` before any
    canonicalization; no duplicate `kid`; a string `issuer`, an integer
    `manifest_version` and a string `issued_at`; the manifest's own signature
    (`verify_key_manifest`); at least one entry that marks a NAMED key
    `compromised`; and evidence whose `entry` is the one computed from THIS
    manifest.

    Two of those exist because the CONSUMER reads them, and a declaration
    missing either is one the verifier authenticates and then ignores — the
    worst kind of artifact to ship, because it looks like a declaration and
    does nothing. `verify._vouching_signers` abandons a claim whose
    `issued_at` is not a string (it has no instant to check a signer's
    validity window against), and `verify._entries_for_kid` selects entries by
    `kid`, so an entry that says `compromised` without naming a key marks
    nothing for anyone. Neither is a shape this module invents: if the
    consumer's rules move, these two move with them.

    What is deliberately NOT checked: the status of the key that SIGNED the
    declaration. §19.3 item 3a does not consult it («status deliberately NOT
    consulted», `attest-v0.2.md:1150`), and vector `41p` pins a declaration
    signed by a compromised key as one that still establishes the status
    floor. Rejecting it here would confuse a claim's VALIDITY with its ability
    to carry a cutoff — two different questions, the second answered by
    `claim_capabilities`.
    """
    own_manifest = _own_object(manifest, "compromise declaration manifest")
    own_evidence = _own_object(evidence, "compromise evidence")
    entries = _manifest_key_entries(own_manifest, "compromise declaration manifest")
    duplicates = manifests.duplicate_kids(entries)
    if duplicates:
        raise ViewError(f"compromise declaration manifest lists duplicate kid(s): {duplicates}")
    if not isinstance(own_manifest.get("issuer"), str):
        raise ViewError("compromise declaration manifest 'issuer' must be a string")
    if not _is_int(own_manifest.get("manifest_version")):
        raise ViewError("compromise declaration manifest 'manifest_version' must be an integer")
    if not isinstance(own_manifest.get("issued_at"), str):
        raise ViewError(
            "compromise declaration manifest 'issued_at' must be a string: without it no "
            "verifier can date the declaration against a signer's validity window, and the "
            "claim authenticates for nobody (verify._vouching_signers)"
        )
    if not manifests.verify_key_manifest(own_manifest):
        raise ViewError(
            "compromise declaration manifest is not self-consistent: its own "
            "signature does not verify against a key it lists"
        )
    if not any(
        isinstance(entry, dict)
        and entry.get("status") == _COMPROMISED
        and isinstance(entry.get("kid"), str)
        for entry in entries
    ):
        raise ViewError(
            "compromise declaration manifest marks no NAMED key 'compromised': an entry "
            "without a string 'kid' is looked up by no verifier (verify._entries_for_kid), "
            "so the declaration declares nothing"
        )
    _require_evidence_shape(
        own_evidence, _key_manifest_log_entry(own_manifest), "compromise evidence"
    )
    claim = {"manifest": own_manifest, "evidence": own_evidence}
    _admissible(claim, "compromise claim", nesting=canon.VIEW_MEMBER_NESTING)
    return claim


def build_compromise_view(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A compromise view: every claim rebuilt, in the order given.

    Rebuilding rather than trusting the caller's objects is what makes this a
    producer: a claim that would not be BUILT is a claim that must not be
    shipped, whoever assembled it.
    """
    own = _own_list(claims, "compromise view")
    if len(own) > _MAX_COMPROMISE_CLAIMS:
        raise ViewError(f"compromise view exceeds {_MAX_COMPROMISE_CLAIMS} claims: {len(own)}")
    built: list[dict[str, Any]] = []
    for index, claim in enumerate(own):
        what = f"compromise view claim {index}"
        if not isinstance(claim, dict):
            raise ViewError(f"{what} must be an object, got {type(claim).__name__}")
        _closed_object(claim, ("manifest", "evidence"), (), what)
        built.append(build_compromise_claim(claim["manifest"], claim["evidence"]))
    return _deduplicated(built, "compromise view")


# --- transfer claims (v0.2 §17.1) --------------------------------------------


def build_transfer_claim(record: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """One `{record, evidence}` transfer claim, or `ViewError`.

    The record's six members are validated — both ULIDs, the new holder's
    32-byte Ed25519 public key, the round-tripping timestamp, the closed
    `{sig}` holder authorization and the issuer's signature block — BEFORE
    `transfer.record_hash` canonicalizes anything, so a malformed record never
    reaches the hash that names it in the log.

    No `anchors` is required. A transfer claim carries weight at `logged`
    standing (`transfer.record_logged_standing`), so demanding an anchor here
    would refuse claims the verifier accepts.
    """
    own_record = _own_object(record, "transfer record")
    own_evidence = _own_object(evidence, "transfer evidence")
    _closed_object(own_record, _TRANSFER_RECORD_MEMBERS, (), "transfer record")
    for member in ("receipt_id", "new_receipt_id"):
        value = own_record[member]
        if not isinstance(value, str) or not _RECEIPT_ID_RE.fullmatch(value):
            raise ViewError(f"transfer record '{member}' must be a ULID: {value!r}")
    if _strict_b64u_decode(own_record["new_holder_pubkey"], _ED25519_PUB_LEN) is None:
        raise ViewError(
            "transfer record 'new_holder_pubkey' must be canonical base64url of a "
            f"{_ED25519_PUB_LEN}-byte Ed25519 public key"
        )
    if not _round_trips(own_record["transferred_at"]):
        raise ViewError(
            "transfer record 'transferred_at' must be a zero-padded UTC timestamp "
            f"({_DATE_FMT}): {own_record['transferred_at']!r}"
        )
    if not _valid_holder_authorization_shape(own_record["holder_authorization"]):
        raise ViewError(
            "transfer record 'holder_authorization' must be exactly {'sig': <base64url "
            "of a 64-byte Ed25519 signature>}"
        )
    kid = _signature_block_kid(own_record["signature"], "transfer record")
    entry = _validated_entry(
        {
            "type": "transfer-record",
            "issuer": _issuer_of_kid(kid),
            "record_sha256": transfer.record_hash(own_record),
        },
        "transfer record",
    )
    _require_evidence_shape(own_evidence, entry, "transfer evidence")
    claim = {"record": own_record, "evidence": own_evidence}
    _admissible(claim, "transfer claim", nesting=canon.VIEW_ARRAY_ELEMENT_NESTING)
    return claim


def build_transfer_view(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A transfer view: every claim rebuilt, in the order given."""
    own = _own_list(claims, "transfer view")
    if len(own) > transfer.MAX_TRANSFER_CLAIMS:
        raise ViewError(f"transfer view exceeds {transfer.MAX_TRANSFER_CLAIMS} claims: {len(own)}")
    built: list[dict[str, Any]] = []
    for index, claim in enumerate(own):
        what = f"transfer view claim {index}"
        if not isinstance(claim, dict):
            raise ViewError(f"{what} must be an object, got {type(claim).__name__}")
        _closed_object(claim, ("record", "evidence"), (), what)
        built.append(build_transfer_claim(claim["record"], claim["evidence"]))
    return _deduplicated(built, "transfer view")


# --- revocation views (v0.2 §8/§12) ------------------------------------------


def build_revocation_view(
    records: list[dict[str, Any]], key_manifest: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """The `revocation-view.json` array every consumer already reads (D12).

    Accepts both statuses §12 registers — `revoked` and `transferred` — because
    both are carried on this one rail: `attest transfer record` has always
    emitted a `transferred` record, and a view that dropped it would hide a
    transfer from the verifier.

    `key_manifest`, when given, is the issuer's key manifest every record must
    verify against (`revocation.verify_record`): the signer key `active`, its
    window covering the record's own signed `revoked_at`, hybrid AND rule
    included. Without it the records are checked for SHAPE only — which is the
    right default for a holder assembling a view out of records they were
    handed and cannot yet authenticate.
    """
    own_records = _own_list(records, "revocation view")
    if len(own_records) > revocation.MAX_REVOCATION_RECORDS:
        raise ViewError(
            f"revocation view exceeds {revocation.MAX_REVOCATION_RECORDS} records: "
            f"{len(own_records)}"
        )
    own_manifest = (
        None if key_manifest is None else _own_object(key_manifest, "issuer key manifest")
    )
    built: list[dict[str, Any]] = []
    for index, record in enumerate(own_records):
        what = f"revocation record {index}"
        if not isinstance(record, dict):
            raise ViewError(f"{what} must be an object, got {type(record).__name__}")
        _closed_object(record, _REVOCATION_RECORD_MEMBERS, (), what)
        receipt_id = record["receipt_id"]
        if not isinstance(receipt_id, str) or not _RECEIPT_ID_RE.fullmatch(receipt_id):
            raise ViewError(f"{what} 'receipt_id' must be a ULID: {receipt_id!r}")
        status = record["status"]
        # `isinstance` FIRST and not as a formality: `x in frozenset` hashes
        # `x`, and an untrusted `status` that arrives as a list or a dict makes
        # that raise `TypeError` — an exception outside this module's contract,
        # escaping from a membership test that looks total.
        if not isinstance(status, str) or status not in _REVOCATION_STATUSES:
            raise ViewError(
                f"{what} 'status' must be one of {sorted(_REVOCATION_STATUSES)}: {status!r}"
            )
        if not _round_trips(record["revoked_at"]):
            raise ViewError(
                f"{what} 'revoked_at' must be a zero-padded UTC timestamp "
                f"({_DATE_FMT}): {record['revoked_at']!r}"
            )
        _signature_block_kid(record["signature"], what)
        if own_manifest is not None and not revocation.verify_record(record, own_manifest):
            raise ViewError(
                f"{what} signature does not verify against the key manifest given: the "
                "signer must be an active key of a self-consistent manifest, with its "
                "validity window covering 'revoked_at'"
            )
        _admissible(record, what, nesting=canon.VIEW_ARRAY_ELEMENT_NESTING)
        built.append(record)
    return _deduplicated(built, "revocation view")


# --- local diagnostics for one compromise claim (D13) ------------------------


def _preflight_trust_material(trusted_manifest: dict[str, Any], chain: list[Any] | None) -> None:
    """Refuse ambiguous or inauthentic trust material before classifying (regola 0-bis).

    Composed here, from the three PUBLIC helpers of `manifests.py`, in the same
    order `verify()`'s own preflight uses (`verify.py:2895-2955`): the `keys[]`
    ceiling, `duplicate_kids` on the head, `manifest_signature_is_authentic` on
    the head, then `duplicate_kids` on every chain member.

    The same property is therefore read in two places, and that is a decision,
    not an oversight: it is duplication of CALLS, not of logic. Both readers
    ask `manifests.py`, which is the single source of the ambiguity rule — a
    change to that rule lands in one file and reaches both. Extracting a shared
    helper out of `verify()` was tried and rejected: the extraction could not
    preserve the interleaving of a payload-dependent warning that sits between
    two of these checks, and `verify.py` stays byte-identical instead.

    The warning `mixed_keyset_active_ed_only_sibling` deliberately has no place
    here: it depends on the RECEIPT's payload, which a claim diagnostic never
    holds.
    """
    ambiguous = "trusted material is ambiguous or inauthentic"
    entries = trusted_manifest.get("keys")
    if not isinstance(entries, list):
        raise ViewError(f"{ambiguous}: trusted manifest 'keys' must be an array")
    if len(entries) > manifests.MAX_MANIFEST_KEYS:
        raise ViewError(
            f"{ambiguous}: trusted manifest exceeds {manifests.MAX_MANIFEST_KEYS} keys "
            f"({len(entries)} entries)"
        )
    duplicates = manifests.duplicate_kids(entries)
    if duplicates:
        raise ViewError(f"{ambiguous}: trusted manifest lists duplicate kid(s): {duplicates}")
    if not manifests.manifest_signature_is_authentic(trusted_manifest):
        raise ViewError(f"{ambiguous}: the trusted manifest signature does not verify")
    for index, member in enumerate(chain or []):
        if not isinstance(member, dict):
            continue
        # Exactly what `verify()`'s own preflight asks of a chain member, and
        # nothing more: `duplicate_kids` alone, which ignores non-list input by
        # documented design. A type check or a ceiling added here would refuse
        # material the verifier admits, and this classifier would then answer a
        # question about a chain no verifier would have rejected.
        member_duplicates = manifests.duplicate_kids(member.get("keys"))
        if member_duplicates:
            raise ViewError(
                f"{ambiguous}: chain member {index} lists duplicate kid(s): {member_duplicates}"
            )


def _declared_compromised_kids(
    claim_manifest: dict[str, Any], trusted_manifest: dict[str, Any]
) -> list[str]:
    """Every kid the claim marks `compromised` that the trusted manifest lists,
    in the claim's own order, each reported once."""
    kids: list[str] = []
    entries = claim_manifest.get("keys")
    if not isinstance(entries, list):
        return kids
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") != _COMPROMISED:
            continue
        kid = entry.get("kid")
        if not isinstance(kid, str) or kid in kids:
            continue
        if manifests.find_key(trusted_manifest, kid) is not None:
            kids.append(kid)
    return kids


def _cutoff_axis(
    authenticated: tuple[Any, ...],
    trusted_manifest: dict[str, Any],
    chain: list[Any] | None,
    issuer_id: str,
    log_keys: list[tlog.LogKey] | None,
    anchor_policy: anchor.AnchorPolicy | None,
) -> str:
    """`not_evaluated` / `not_established` / `established:<T>`.

    The word "cutoff" never appears with a time attached unless the caller
    supplied BOTH pins: a cutoff exists only after `evaluate_transparency`
    reaches `anchored_before` under the verifier's own log keys and anchor
    policy (P12). The presence of an `anchors` member proves nothing, and that
    is why it is a separate axis.
    """
    if log_keys is None or anchor_policy is None:
        return "not_evaluated"
    if not authenticated:
        return "not_established"
    try:
        resolved = _resolve_compromise_cutoff(
            authenticated, trusted_manifest, chain, issuer_id, log_keys, anchor_policy, []
        )
    # A `TransparencyError` from an empty or disagreeing pin set is the
    # CALLER's configuration being wrong, never a verdict about the claim.
    except Exception as exc:
        raise ViewError(f"the pinned log configuration is unusable: {exc}") from exc
    if resolved is None:
        return "not_established"
    if resolved.tzinfo is not None:
        resolved = resolved.astimezone(UTC)
    return f"established:{resolved.strftime(_DATE_FMT)}"


def claim_capabilities(
    claim: dict[str, Any],
    trusted_manifest: dict[str, Any],
    chain: list[dict[str, Any]] | None,
    *,
    log_keys: list[tlog.LogKey] | None = None,
    anchor_policy: anchor.AnchorPolicy | None = None,
) -> dict[str, dict[str, str]]:
    """What one compromise claim can and cannot do, per compromised kid.

    A LOCAL Python diagnostic, relative to the trusted manifest passed in. It
    has no TypeScript twin and is not a protocol classification: do not put its
    strings on the wire, and do not read a verdict about a receipt out of them.

    For every kid the claim marks `compromised` and the trusted manifest lists,
    four INDEPENDENT axes — kept separate on purpose, because collapsing them
    into one synthetic `cutoff_capable` is what made the earlier design
    unanswerable (F3):

    - `floor`: `established` / `ignored` — does the claim authenticate at all
      (§19.3 items 1, 2, 3a)? A claim signed by a key the trusted material does
      not vouch for is `ignored`.
    - `cutoff_signer`: `eligible` / `ineligible` — could its signer carry a
      §19.3 item 3b cutoff, under the `delta` rule where only chain members the
      trusted manifest itself vouches for may deny one?
    - `anchor_evidence`: `present_unverified` / `absent` — is there an `anchors`
      member at all? Present is not verified, and this axis never claims it is.
    - `cutoff`: `not_evaluated` / `not_established` / `established:<T>` — only
      with `log_keys` AND `anchor_policy`; without them the answer is that the
      question was not asked.

    Raises `ViewError` when the trusted material is ambiguous or inauthentic:
    such material yields no classification at all, not a lenient one.
    """
    own_claim = _own_object(claim, "compromise claim")
    own_trusted = _own_object(trusted_manifest, "trusted key manifest")
    own_chain = None if chain is None else _own_list(chain, "manifest chain")
    _preflight_trust_material(own_trusted, own_chain)
    issuer_id = own_trusted.get("issuer")
    if not isinstance(issuer_id, str):
        raise ViewError("trusted material is ambiguous or inauthentic: 'issuer' must be a string")
    claim_manifest = own_claim.get("manifest")
    if not isinstance(claim_manifest, dict):
        raise ViewError("compromise claim 'manifest' must be an object")
    evidence = own_claim.get("evidence")
    materialized = _materialize_compromise_view([own_claim])
    denying = _cutoff_denying_manifests(own_trusted, own_chain, issuer_id)
    report: dict[str, dict[str, str]] = {}
    for kid in _declared_compromised_kids(claim_manifest, own_trusted):
        trusted_entry = manifests.find_key(own_trusted, kid)
        if trusted_entry is None:  # pragma: no cover - excluded by the preflight
            continue
        authenticated = _authenticated_compromise_claims(
            materialized, own_trusted, trusted_entry, own_chain, issuer_id, kid, []
        )
        report[kid] = {
            "floor": "established" if authenticated else "ignored",
            "cutoff_signer": (
                "eligible"
                if any(_claim_has_cutoff_signer(c, denying) for c in authenticated)
                else "ineligible"
            ),
            "anchor_evidence": (
                "present_unverified"
                if isinstance(evidence, dict) and "anchors" in evidence
                else "absent"
            ),
            "cutoff": _cutoff_axis(
                authenticated, own_trusted, own_chain, issuer_id, log_keys, anchor_policy
            ),
        }
    return report
