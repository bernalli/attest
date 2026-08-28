"""Publisher authorization manifests — may this seller sell? (v0.2 §20).

A publisher authorization manifest is a CLOSED, hybrid-signed side-document
published by the RIGHTS HOLDER, the fifth sibling of the revocation record
(v0.1 §12), the transfer record (§17.1), the sunset grant and the cessation
declaration (§18.2/§18.4): unknown members are rejected outright (the
log-entry discipline of §8), it is JCS-canonicalized (v0.1 §9), and its own
signature is verified under the §13 hybrid AND-rule through the single shared
primitive `manifests.verify_signature_block`. It is ONE document per publisher
listing the authorized issuers, never one document per publisher-issuer
relationship: with a single versioned manifest, revoking an issuer is
publishing version N+1 in which that issuer's entry REMAINS with its window
closed, and rollback of that revocation is the same "serve an old manifest"
attack `manifest_version` currency already treats.

This module holds the PRIMITIVES §20 is built out of, and nothing that reaches
a verdict:

- building the document (§20.2) and authenticating it, fail-closed on every
  malformed, wrong-typed, out-of-window or unsigned input, never raising;
- `authorization_hash` — `SHA-256(JCS(document))` over the ENTIRE signed
  document, its own `signature` member included, the identical hashing
  discipline `revocation.record_hash`, `transfer.record_hash` and
  `grant.grant_hash` already establish, and what a `publisher-authorization`
  log entry (§8, the SIXTH entry type) commits to;
- the membership half of §20.4 step 9 — `entry_for_issuer` and
  `entry_authorizes_receipt`, the window evaluated against the RECEIPT's own
  `issued_at` so that de-authorization stays prospective (§20.2);
- the structural ceiling of the evidence channel (§20.3), which counts and
  never inspects;
- `is_authorization_version`, the ONE predicate shared by the document's
  `authorization_version` (§20.2) and the view's
  `current_authorization_version` (§20.3) — two spellings would diverge
  exactly on the boundary that decides whether a denial holds or degrades to
  `unattested` (§20.4 step 10).

Authority EVALUATION — §20.4's ordered steps, the `publisher_authority` and
`publisher_authority_trust` result components, the resolution of the
publisher's key manifest and the trust ladder — needs the receipt payload, a
trust store and the caller's view in hand, so it belongs to the module that
has them, exactly as grant evaluation belongs to `verify.py` rather than to
`grant.py`.

Predicates that already exist are IMPORTED, never restated: the lowercase-DNS
shape, the strictly-ascending array test, the non-empty-string test, the scope
shape and the signed-document authentication from `grant`; the strict UTC
wire-timestamp shape and its parse from `transfer`; key lookup, signature-block
signing/verification and manifest self-consistency from `manifests`. A second
spelling of any of them is a place two implementations can drift apart, which
is the one thing this design spends most of its prose preventing.
"""

from __future__ import annotations

import hashlib
from typing import Any, cast

from attest import canon, grant, keys, manifests, pq, transfer

# Registry-governed vocabulary (attest-versioning.md §6.11). Named constants
# rather than inline literals so a registration is one edit here.
PERMISSION_ISSUE = "issue"
# Registered `reserved` (§6.11) and deliberately unreachable: sub-licensing
# needs document chains this revision excludes. An entry listing it is NOT
# thereby invalid — the permission simply contributes nothing, which is why
# this constant exists and NO code path honors it.
PERMISSION_DELEGATE = "delegate"

# Structural ceilings, both COUNT ceilings in the §18.4 sense — checked before
# any cryptographic work, because each element costs a hybrid signature
# verification and a byte cap alone is therefore not a ceiling.
#
# `MAX_AUTHORIZED_ISSUERS` bounds one document's `authorized_issuers` (§20.2),
# in the artifacts[] class of v0.1 §11.3; `MAX_AUTHORITY_DOCUMENTS` bounds the
# candidate documents a caller may supply in `authority_view.authorizations`
# (§20.3), in the `later_grants` class of §18.4.
MAX_AUTHORIZED_ISSUERS = 4096
MAX_AUTHORITY_DOCUMENTS = 64

# The five members of the document and the five of each entry (§20.2). Both are
# CLOSED — the log-entry discipline of §8, not the receipt payload's tolerant
# one — so an unknown member is not a warning but a rejection.
_AUTHORIZATION_MEMBERS = frozenset(
    {"authorization_version", "publisher", "authorized_issuers", "issued_at", "signature"}
)
_ENTRY_MEMBERS = frozenset({"issuer_id", "valid_from", "valid_to", "permissions", "scope"})


# --- the shared version predicate --------------------------------------------


def is_authorization_version(value: object) -> bool:
    """Whether `value` is an `authorization_version` (§20.2): an integer —
    never a `bool`, which Python would otherwise let through — in
    `[1, 2**53 - 1]`, the attest-JCS safe-integer range.

    ONE predicate, used in TWO places on purpose: the document's own
    `authorization_version` (§20.2's shape) and the view's
    `current_authorization_version` (§20.3). §20.4 step 10 makes a denial hang
    on those two being EQUAL, so two spellings of "well-formed version" would
    diverge exactly on the boundary that decides whether `unauthorized` holds
    or degrades to `unattested` — and a malformed assertion is treated as
    ABSENT, never as fatal, so the divergence would be silent.
    """
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= grant._MAX_JCS_INTEGER
    )


# --- shared successor-discipline predicates (§20.2) --------------------------


def same_instant(left: str | None, right: str | None) -> bool:
    """Whether two optional window endpoints denote the same instant (§20.2).

    Two `null` endpoints compare equal; a `null` endpoint and a timestamp do
    not. Non-null endpoints are parsed with the wire timestamp grammar before
    comparison so carry checks and ordering checks use one instant spelling.

    PRECONDITION, and the ONE thing an importer must read: a non-null endpoint
    that is not a well-formed wire timestamp RAISES (`transfer._parse_date`).
    This predicate is therefore NOT the never-raise surface of §20.3 — the
    builder wants it loud, and §20.4 step 7 may call it only on documents
    ALREADY ADMITTED, whose `valid_to` members `_valid_authorization_shape`
    has proven parseable. Reaching it from anything less than an admitted
    document breaks "hostile CONTENT inside a well-shaped view never raises":
    validate first, or wrap at the call site.
    """
    if left is None or right is None:
        return left is None and right is None
    return transfer._parse_date(left) == transfer._parse_date(right)


def window_spent_at(valid_to: str | None, instant: str) -> bool:
    """Classify an entry window relative to `instant` under §20.2.

    The window is spent when `valid_to` is non-null and strictly earlier than
    `instant`; otherwise it is live. Non-null timestamps are parsed before the
    order comparison.

    PRECONDITION: as `same_instant` — a non-null `valid_to` or an `instant`
    that is not a well-formed wire timestamp RAISES, and §20.4 step 7 may
    call this only on ADMITTED documents, never on caller-supplied content
    that has not passed `_valid_authorization_shape`.
    """
    if valid_to is None:
        return False
    return transfer._parse_date(valid_to) < transfer._parse_date(instant)


# --- shape (§20.2) ------------------------------------------------------------


def _valid_entry_shape(entry: object) -> bool:
    """The closed five-member shape of one `authorized_issuers` entry (§20.2).

    `permissions` values are OPEN beyond the registry (§18.2's directional
    rule, restated by §20.2): an unregistered value is carried and never fatal,
    because rejecting the document over it would make a later registration
    retroactively invalidate documents that predate it. What the array must be
    is non-empty, sorted and duplicate-free — the wire order pinned so two
    canonicalizations of one document stay byte-identical.
    """
    if not isinstance(entry, dict) or set(entry) != _ENTRY_MEMBERS:
        return False
    valid_to = entry["valid_to"]
    permissions = entry["permissions"]
    scope = entry["scope"]
    return (
        grant._is_dns_name(entry["issuer_id"])
        and transfer._valid_utc_timestamp(entry["valid_from"])
        and (valid_to is None or transfer._valid_utc_timestamp(valid_to))
        and isinstance(permissions, list)
        and bool(permissions)
        and grant._sorted_unique(permissions, grant._is_non_empty_str)
        and (scope is None or grant._scope_or_none(scope) is not None)
    )


def _valid_authorization_shape(document: object) -> bool:
    """The closed five-member shape of §20.2, checked before any cryptographic
    work — the 4096-entry ceiling included, so a document that would cost
    thousands of comparisons is refused on its count first.

    `authorized_issuers` is sorted STRICTLY ascending by `issuer_id` at Unicode
    code point (§18.2's rule), which is the SAME test that rejects a duplicate:
    a repeated `issuer_id` is not strictly ascending. A second, separate
    duplicate check would be a second place to drift, and §20.2 requires the
    rejection to happen here — before any cryptographic work — precisely so
    that the order of this array can never decide an outcome.

    Python compares `str` by code point, which is what §18.2 requires; a
    UTF-16 implementation must sort by code point explicitly (the divergence
    attest-v0.2.md documents for §18.2's own sorted arrays).
    """
    if not isinstance(document, dict) or set(document) != _AUTHORIZATION_MEMBERS:
        return False
    if not is_authorization_version(document["authorization_version"]):
        return False
    if not grant._is_dns_name(document["publisher"]):
        return False
    entries = document["authorized_issuers"]
    if not isinstance(entries, list) or len(entries) > MAX_AUTHORIZED_ISSUERS:
        return False
    if not all(_valid_entry_shape(entry) for entry in entries):
        return False
    if not grant._sorted_unique([entry["issuer_id"] for entry in entries], grant._is_dns_name):
        return False
    return transfer._valid_utc_timestamp(document["issued_at"]) and isinstance(
        document["signature"], dict
    )


# --- building (§20.2) ---------------------------------------------------------


def _reject_non_successor(
    authorization_version: int,
    authorized_issuers: list[Any],
    issued_at: str,
    previous: object,
) -> None:
    """Raise `ValueError` unless the document about to be signed is a
    CONFORMING successor of `previous` (§20.2, entry preservation and successor
    discipline).

    This is not the mitigation — a document written by hand never passes
    through this builder, and §20.4 step 7 is where a verifier excludes a
    non-conforming successor it can prove. What it removes is the honest
    publisher's accident: deleting an entry instead of closing its window,
    moving a `valid_from`, back-dating a closure over receipts already issued
    inside it.

    A `previous` supplied but unreadable is refused rather than skipped: a
    predecessor that cannot be compared cannot show the successor conforming,
    and silently dropping the check is how a mitigation becomes decorative.
    """
    if not isinstance(previous, dict):
        raise ValueError("previous must be a publisher authorization document")
    previous_version = previous.get("authorization_version")
    if not is_authorization_version(previous_version) or not is_authorization_version(
        authorization_version
    ):
        raise ValueError(
            "authorization_version must be an integer in "
            f"[1, {grant._MAX_JCS_INTEGER}] in both documents"
        )
    # Both are `is_authorization_version` above; the cast carries that to the
    # type checker, which cannot narrow through a plain predicate.
    if authorization_version <= cast(int, previous_version):
        raise ValueError(
            f"authorization_version {authorization_version} is not above the predecessor's "
            f"{previous_version}: the version is monotone per publisher"
        )
    previous_issued_at = previous.get("issued_at")
    if not transfer._valid_utc_timestamp(previous_issued_at):
        raise ValueError("previous.issued_at must be an ISO-8601 UTC timestamp")
    previous_entries = previous.get("authorized_issuers")
    if not isinstance(previous_entries, list):
        raise ValueError("previous.authorized_issuers must be an array")
    if not isinstance(authorized_issuers, list):
        raise ValueError("authorized_issuers must be an array")

    for previous_entry in previous_entries:
        if not isinstance(previous_entry, dict):
            raise ValueError("previous.authorized_issuers entries must be objects")
        issuer_id = previous_entry.get("issuer_id")
        # Every entry carrying this `issuer_id` is checked, not merely the
        # first: on a duplicate the array's ORDER must not decide whether the
        # successor conforms.
        successors = [
            entry
            for entry in authorized_issuers
            if isinstance(entry, dict) and entry.get("issuer_id") == issuer_id
        ]
        if not successors:
            raise ValueError(
                f"entry for {issuer_id!r} is absent: an entry, once published, must appear in "
                "every later version — de-authorization CLOSES the window, it never deletes"
            )
        for entry in successors:
            _reject_non_successor_entry(
                previous_entry, entry, cast(str, previous_issued_at), issued_at
            )


def _reject_non_successor_entry(
    previous_entry: dict[str, Any],
    entry: dict[str, Any],
    previous_issued_at: str,
    issued_at: str,
) -> None:
    """The per-entry half of §20.2's successor discipline.

    `issued_at` is the successor document's own timestamp; for live-window
    restrictions it bounds the closure from above exactly as
    `previous_issued_at` bounds it from below.
    """
    issuer_id = previous_entry.get("issuer_id")
    for side, source in (("previous", previous_entry), ("successor", entry)):
        missing = sorted({"valid_from", "valid_to"} - set(source))
        if missing:
            raise ValueError(
                f"the {side} entry {issuer_id!r} does not carry {' and '.join(missing)}: an entry "
                "that cannot be compared cannot be shown conforming, and an ABSENT member is "
                "never read as an open-ended window"
            )
    if entry.get("valid_from") != previous_entry.get("valid_from"):
        raise ValueError(
            f"valid_from of entry {issuer_id!r} changed: within an entry shared across "
            "versions it MUST NOT change"
        )
    previous_valid_to = previous_entry.get("valid_to")
    valid_to = entry.get("valid_to")
    if previous_valid_to is not None and not transfer._valid_utc_timestamp(previous_valid_to):
        raise ValueError(
            f"previous.valid_to of entry {issuer_id!r} must be an ISO-8601 UTC timestamp "
            "to be shown conforming against the successor"
        )
    if valid_to is not None and not transfer._valid_utc_timestamp(valid_to):
        raise ValueError(
            f"valid_to of entry {issuer_id!r} must be an ISO-8601 UTC timestamp to be shown "
            "conforming against the predecessor"
        )
    previous_window_end = cast(str | None, previous_valid_to)
    window_end = cast(str | None, valid_to)
    if same_instant(previous_window_end, window_end):
        return

    if previous_window_end is not None:
        if not transfer._valid_utc_timestamp(issued_at):
            raise ValueError(
                "issued_at must be an ISO-8601 UTC timestamp to classify the predecessor's "
                "window as spent or live"
            )
        if window_spent_at(previous_window_end, issued_at):
            raise ValueError(
                f"the spent window of entry {issuer_id!r} moved: a window no longer covering "
                "this document's issued_at is a historical fact and MUST NOT move in either "
                "direction"
            )
    if window_end is None:
        return
    if previous_window_end is not None and not (
        transfer._parse_date(window_end) < transfer._parse_date(previous_window_end)
    ):
        return
    # A live-window restriction is bounded on BOTH sides: the predecessor's
    # `issued_at` below and this successor document's `issued_at` above.
    if not transfer._valid_utc_timestamp(issued_at):
        raise ValueError(
            "issued_at must be an ISO-8601 UTC timestamp to bound a newly introduced closure"
        )
    closure = transfer._parse_date(window_end)
    if closure < transfer._parse_date(previous_issued_at):
        raise ValueError(
            f"the closure of entry {issuer_id!r} is back-dated before the predecessor's "
            f"issued_at {previous_issued_at}: a closure may not uncover receipts already "
            "issued inside the window"
        )
    if closure > transfer._parse_date(issued_at):
        raise ValueError(
            f"the closure of entry {issuer_id!r} is post-dated after this document's own "
            f"issued_at {issued_at}: a closure may not be post-dated into the future"
        )


def build_authorization(
    authorization_version: int,
    publisher: str,
    authorized_issuers: list[dict[str, Any]],
    issued_at: str,
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a publisher-signed authorization manifest (§20.2), five members.

    `signing_kp` mirrors `manifests.build_key_manifest`/`grant.build_grant`: a
    `pq.HybridSigningKeys` produces a `signature` block carrying both the
    Ed25519 `sig` leg and the `sig_ml_dsa_65` leg (see
    `manifests.sign_signature_block`); a plain `keys.SigningKeyPair` keeps the
    Ed25519-only shape, which a hybrid-keyed publisher's manifest entry will
    then refuse under the §13 AND-rule.

    Like its siblings, this builder does NOT validate the body it signs —
    building a deliberately malformed document is how the verification side
    gets tested, and a document that does not conform simply never
    authenticates — with ONE exception. When `previous` (the predecessor
    document) is supplied, §20.2's entry-preservation and successor discipline
    is enforced BEFORE any signature is computed, and a violation raises
    `ValueError`: a deleted entry, a moved `valid_from`, a spent window moved
    in either direction, or a live-window restriction outside the two bounds
    §20.2 sets on it — no earlier than the predecessor's own `issued_at`
    (back-dating uncovers receipts already issued inside the window) and no
    later than this document's own `issued_at` (a closure may not be
    post-dated into the future). A version not above the predecessor's is
    refused for the same reason. `previous=None` leaves behaviour byte-identical to a builder
    without this argument.
    """
    if previous is not None:
        _reject_non_successor(authorization_version, authorized_issuers, issued_at, previous)
    body: dict[str, Any] = {
        "authorization_version": authorization_version,
        "publisher": publisher,
        "authorized_issuers": authorized_issuers,
        "issued_at": issued_at,
    }
    body["signature"] = manifests.sign_signature_block(canon.canonical_bytes(body), signing_kp, kid)
    return body


# --- hashing (§20.2, §8) ------------------------------------------------------


def authorization_hash(document: dict[str, Any]) -> str:
    """`SHA-256(JCS(document))`, 64 lowercase hex — the ENTIRE signed document,
    INCLUDING its own `signature` member (unlike the body-only bytes the
    signature itself is computed over).

    This is what a `publisher-authorization` log entry commits to (§8, the
    SIXTH entry type) and what deduplicates two copies of one document at
    §20.4 step 6: the SAME `canon.canonical_bytes` this module already uses to
    build and verify the signature — one canonical form, reused, never a second
    one invented for the binding. Mirrors `grant.grant_hash` exactly.
    """
    return hashlib.sha256(canon.canonical_bytes(document)).hexdigest()


# --- authentication (§20.2) ---------------------------------------------------


def verify_authorization_signature(document: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify a document's own signature against an ALREADY self-verified
    `key_manifest` — exactly `verify_authorization` minus the
    `manifests.verify_key_manifest` self-consistency check, mirroring
    `grant.verify_grant_signature`.

    The closed five-member shape is checked FIRST: a document whose signature
    happens to verify over a malformed member (any string canonicalizes fine,
    so the signature alone cannot catch this) is still rejected — and §20.2
    requires shape rejection to precede any cryptographic work. Fails closed on
    every malformed/wrong-typed/unsigned/out-of-window input, and NEVER raises:
    a supplied document arrives on the caller's evidence rail and every one of
    its members is assumed hostile.

    This is AUTHENTICATION only. The triple domain binding of §20.4 step 6 —
    the document's `publisher` equal to the resolving manifest's `issuer` equal
    to the receipt's `work.publisher_id` — is a SEPARATE check, because §20.4
    reports its failure differently (`publisher_authority_trust:
    "signer_mismatch"` with `authorization_signer_not_publisher`, rather than a
    plain rejection). Compose it from `grant.signer_domain` and the two
    documents.

    PRECONDITION: the caller has already established
    `manifests.verify_key_manifest(key_manifest)`. Callers checking many
    documents against ONE manifest hoist that call out of their loop.
    """
    try:
        if not _valid_authorization_shape(document):
            return False
        return grant._verify_signed_document(document, key_manifest, "issued_at")
    # Broader than this package's usual narrow tuple, deliberately: §20.3 makes
    # "hostile CONTENT inside a well-shaped view never raises" normative, and a
    # caller-constructed member can raise ANY exception type. The TypeScript
    # twin's bare `catch` already means this; a narrower clause here is a place
    # the two implementations disagree.
    except Exception:
        return False


def verify_authorization(document: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify a publisher authorization manifest against `key_manifest`,
    mirroring `grant.verify_grant` exactly: the signer key must be **active**
    in a SELF-CONSISTENT `key_manifest`, with its validity window covering the
    document's own `issued_at` (never the verifier's clock), and the signature
    must verify under the §13 hybrid AND-rule — so a classical-only document
    against a hybrid key entry fails closed, exactly as every sibling does.

    Defense-in-depth: `key_manifest` itself must be self-consistent, so a
    fabricated publisher manifest paired with a matching fabricated signature
    cannot verify. Fails closed on every malformed input, never raises.
    """
    try:
        if not _valid_authorization_shape(document):
            return False
        return manifests.verify_key_manifest(key_manifest) and verify_authorization_signature(
            document, key_manifest
        )
    except Exception:  # see verify_authorization_signature
        return False


# --- membership (§20.4 step 9) ------------------------------------------------


def entry_for_issuer(document: object, issuer_id: object) -> dict[str, Any] | None:
    """THE entry whose `issuer_id` equals `issuer_id`, or `None`.

    At most one can exist: a duplicate `issuer_id` is a SHAPE error rejected
    upstream (`_valid_authorization_shape`), so an admitted document never
    carries one. On a document that was NOT admitted this resolves to no entry
    at all rather than to whichever duplicate the presenter placed first —
    §20.2 is explicit that "the order of this array must never be able to
    decide an outcome", and returning the first match is precisely how order
    would decide one. Fails closed on every malformed input, never raises.
    """
    try:
        if not isinstance(document, dict) or not isinstance(issuer_id, str):
            return None
        # `dict.get` reads OWN items only, so an overridden `get` cannot lie;
        # the enclosing `try` is what keeps the never-raise promise against the
        # triggers an own-item read does not cover (`__eq__`, `__getitem__`).
        entries = dict.get(document, "authorized_issuers")
        if not isinstance(entries, list):
            return None
        matches = [
            entry
            for entry in entries
            if isinstance(entry, dict) and dict.get(entry, "issuer_id") == issuer_id
        ]
        return matches[0] if len(matches) == 1 else None
    except Exception:
        return None


def _within_entry_window(issued_at: str, entry: dict[str, Any]) -> bool:
    """Whether `issued_at` falls within the entry's `[valid_from, valid_to]`,
    both bounds INCLUSIVE, `valid_to: null` meaning open-ended.

    The semantics of `verify._within_validity`, which applies the same rule to
    a key entry's window: an unparseable or missing bound never resurrects
    anything into validity. It is written here rather than imported because
    `verify.py` imports the side-document modules and never the reverse —
    importing it back would be a cycle.
    """
    try:
        issued = transfer._parse_date(issued_at)
        valid_from = transfer._parse_date(entry["valid_from"])
    except (KeyError, TypeError, ValueError):
        return False
    if issued < valid_from:
        return False
    valid_to = entry.get("valid_to")
    if valid_to is None:
        return True
    try:
        return issued <= transfer._parse_date(valid_to)
    except (TypeError, ValueError):
        return False


def entry_authorizes_receipt(entry: object, payload: object) -> bool:
    """Whether one `authorized_issuers` entry authorizes THIS receipt — the
    three conjuncts of §20.4 step 9, over an entry already matched by
    `issuer_id`:

    - the receipt's own `issued_at` falls within `[valid_from, valid_to]`;
    - `issue` is among `permissions` (`delegate` is reserved and never
      honored, §6.11);
    - `scope` is `null` — the publisher's entire catalogue — OR the scope
      covers this receipt under §18.4's GRANT-COVERAGE predicate,
      vacuous-quantifier guard included, so an artifact-less receipt is covered
      by no non-null scope.

    The window is evaluated against the RECEIPT's `issued_at` and never the
    verifier's clock: that is what makes de-authorization PROSPECTIVE (§20.2).
    A receipt issued while its issuer was inside an authorized window stays
    authorized forever, exactly as receipts signed while a key was active
    remain valid after that key is retired.

    The entry is held to §20.2's own closed shape FIRST, through the one
    predicate that states it (`_valid_entry_shape`), rather than to a second,
    weaker spelling inline. §20.4 step 9 only ever reaches this with an entry
    of an ADMITTED document, so for every real evaluation the check is free;
    what it buys is that a malformed entry cannot answer `True` on a
    technicality. `permissions: ["issue", {}]` is the shape of that
    technicality — bare membership is blind to the type of what surrounds the
    value it finds — and an ABSENT `scope` member is another: absent is not
    `null`, and must never be read as "the entire catalogue". Fails closed on
    every malformed input and never raises: this runs over a document supplied
    on the caller's evidence rail.
    """
    try:
        if not _valid_entry_shape(entry) or not isinstance(payload, dict):
            return False
        entry = cast(dict[str, Any], entry)
        issuer = payload.get("issuer")
        if not isinstance(issuer, dict) or issuer.get("id") != entry["issuer_id"]:
            return False
        issued_at = payload.get("issued_at")
        if not isinstance(issued_at, str) or not _within_entry_window(issued_at, entry):
            return False
        if PERMISSION_ISSUE not in entry["permissions"]:
            return False
        scope = entry["scope"]
        if scope is None:
            return True
        return grant.grant_covers_receipt({"scope": scope}, payload)
    except Exception:  # see verify_authorization_signature
        return False


# --- the evidence-channel ceiling (§20.3) -------------------------------------


def within_structural_ceiling(authorizations: list[Any] | None) -> bool:
    """Whether the caller-supplied `authority_view.authorizations` array is
    within its COUNT ceiling — `MAX_AUTHORITY_DOCUMENTS`, 64 (§20.3).

    Each element costs a hybrid signature verification, so a byte cap alone is
    not a ceiling, exactly as v0.1 §11.3 and §18.4 already require elsewhere.
    Exceeding it truncates evaluation fail-closed toward `unattested`, never
    toward `authorized` and never toward `unauthorized`.

    This predicate judges COUNT and nothing else: it never indexes, compares,
    hashes or otherwise inspects an element — that is what lets a caller run it
    BEFORE any signature is verified, and a check which does not run first is
    not a ceiling at all. Absent evidence (`None`) is within the ceiling;
    anything that is not an array fails closed.
    """
    # DELEGATED, never restated: `grant._within_ceiling` is the one spelling of
    # a count ceiling in this package, and the TypeScript twin delegates to
    # `withinCeiling` for the same reason. The `try` — not a narrower
    # `isinstance` — is what keeps the never-raise promise against a hostile
    # `__len__`, which is how the two implementations stay identical here.
    try:
        return grant._within_ceiling(authorizations, MAX_AUTHORITY_DOCUMENTS)
    except Exception:
        return False
