"""Sunset grants and cessation declarations — the preservation pledge (v0.2 §18).

A sunset grant is a CLOSED, hybrid-signed side-document published by the RIGHTS
HOLDER (not by the receipt's issuer), structurally a sibling of the revocation
record (`revocation.py`) and the transfer record (`transfer.py`): unknown
members are rejected outright, it is JCS-canonicalized (v0.1 §9), and its own
signature is verified under the §13 hybrid AND-rule through the single shared
primitive `manifests.verify_signature_block`. A receipt hash-binds one such
document through the license term `license.preservation_pledge` (§18.2); that
document is the buyer's FLOOR.

This module holds the PRIMITIVES §18 is built out of, and nothing that reaches
a verdict:

- building and authenticating the grant (§18.2) and the cessation declaration
  (§18.4), both fail-closed on every malformed, wrong-typed, out-of-window or
  unsigned input, and neither ever raising;
- `grant_hash`/`declaration_hash` — `SHA-256(JCS(document))` over the ENTIRE
  signed document, its own `signature` member included, the identical hashing
  discipline `revocation.record_hash`/`transfer.record_hash` already establish;
- the TWO coverage predicates §18.4 deliberately keeps apart —
  `declaration_covers_grant` (two documents of the same shape, series equality
  a CONJUNCT) and `grant_covers_receipt` (a grant against a receipt's older
  `work` block, series equality a SUFFICIENT clause). They are written
  separately on purpose: sharing an implementation would collapse the very
  distinction the specification spends a paragraph drawing;
- the floor-relative non-narrowing ratchet (§18.3) and the prose-divergence
  test that deliberately sits OUTSIDE it;
- the structural ceilings (§18.4), which count and never inspect;
- the audience-bound redemption proof (§18.7).

Grant EVALUATION — §18.4's ordered steps, the `grant`/`grant_trust` result
components, the resolution of the publisher's key manifest and the anchored
fixed-date proof — needs the receipt payload, a trust store and an anchor
policy in hand, so it belongs to the module that has them, exactly as
revocation-class effectiveness belongs to `verify.py` rather than to
`revocation.py`.

Predicates that already exist are IMPORTED, never restated: the lowercase-DNS
and 64-hex shapes from `tlog`, the strict UTC wire-timestamp shape and its
parse from `transfer`, key lookup and signature-block verification from
`manifests`. A second spelling of any of them is a place two implementations
can drift apart, which is the one thing §18 spends most of its prose
preventing.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any, cast

from attest import canon, keys, manifests, pq, tlog, transfer

_ACTIVE = "active"
_MAX_JCS_INTEGER = 2**53 - 1

# The eleven members of a sunset grant (§18.2) and the four of a cessation
# declaration (§18.4). Both documents are CLOSED — the log-entry discipline of
# §8, not the receipt payload's tolerant one — so an unknown member is not a
# warning but a rejection.
_GRANT_MEMBERS = frozenset(
    {
        "grant_version",
        "publisher",
        "scope",
        "permissions",
        "activation",
        "unprotected_build",
        "legal_text_uri",
        "legal_text_sha256",
        "jurisdiction",
        "issued_at",
        "signature",
    }
)
_DECLARATION_MEMBERS = frozenset({"publisher", "scope", "declared_at", "signature"})
_SCOPE_MEMBERS = frozenset({"artifact_series", "artifacts"})
_ACTIVATION_MEMBERS = frozenset({"modes", "fixed_date", "successor_ids"})

# Registry-governed vocabularies (attest-versioning.md §6.8-§6.10). Named
# constants rather than inline literals so a registration is one edit here.
PERMISSION_DELIVER_TO_HOLDER = "deliver-to-holder"
PERMISSION_REDISTRIBUTE_AMONG_HOLDERS = "redistribute-among-holders"

MODE_PUBLISHER_DECLARATION = "publisher-declaration"
MODE_FIXED_DATE = "fixed-date"
# Registered `reserved` (§6.9) and deliberately unreachable: a mode that reads
# meaning into the ABSENCE of a record cannot be sound until a verifier can
# establish freshness. A grant listing it is NOT thereby invalid — the mode
# simply contributes nothing to activation, which is why this constant exists
# and no code path honors it.
MODE_HEARTBEAT_ABSENCE = "heartbeat-absence"

PLEDGE_SUNSET_GRANT_V1 = "sunset-grant-v1"
END_OF_LIFE_SUNSET_GRANT = "sunset-grant"

SIGNER_ROLE_PUBLISHER = "publisher"
SIGNER_ROLE_SUCCESSOR = "successor"

# Fixed literal (§18.7, verbatim) — the domain-separation label for the
# redemption preimage. A NEW preimage rather than a reuse of v0.1 §8.2's
# binding challenge precisely because that one names no recipient, so a
# response produced for one custodian would be replayable at another.
LABEL_REDEMPTION_CHALLENGE = b"Attest-redemption-challenge-v1"
_MIN_REDEMPTION_NONCE_BYTES = 16

# Structural ceilings (§18.4, normative). `later_grants` and supplied
# declarations are attacker-supplied inputs whose elements each cost a hybrid
# signature verification, so a byte cap alone is not a ceiling: the COUNT of
# each is bounded, and the check runs BEFORE any signature work.
_MAX_GRANT_LATER_VERSIONS = 64
_MAX_GRANT_DECLARATIONS = 64


# --- shared shape predicates -------------------------------------------------


def _is_dns_name(value: object) -> bool:
    """The lowercase-DNS shape of `issuer.id`, reused verbatim for
    `publisher`, `work.publisher_id` and every `successor_ids` entry (§18.1)."""
    return isinstance(value, str) and tlog._ISSUER_RE.fullmatch(value) is not None


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and tlog._HEX64_RE.fullmatch(value) is not None


def _is_non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _sorted_unique(values: object, item_ok: Callable[[object], bool]) -> bool:
    """A list whose every item passes `item_ok` and which is STRICTLY
    ascending — one test for the "sorted, duplicate-free" shape §18.2 requires
    of `scope.artifacts`, `permissions`, `activation.modes` and
    `activation.successor_ids`. Set containment later compares these as sets;
    pinning the wire order here is what keeps two canonicalizations of the
    same grant byte-identical."""
    if not isinstance(values, list):
        return False
    if not all(item_ok(item) for item in values):
        return False
    return all(values[i] < values[i + 1] for i in range(len(values) - 1))


def _scope_or_none(scope: object) -> dict[str, Any] | None:
    """`scope` itself when it is `{artifact_series: string|null, artifacts:
    [64-hex, ...]}` with at least one of the two non-empty (§18.2), else
    `None`. The same shape is required of a cessation declaration's own
    `scope`.

    Returning the validated object rather than a bare boolean is what lets
    every caller index it afterwards without a second, weaker check standing
    in for the first one.
    """
    if not isinstance(scope, dict) or set(dict.keys(scope)) != _SCOPE_MEMBERS:
        return None
    series = dict.get(scope, "artifact_series")
    if series is not None and not _is_non_empty_str(series):
        return None
    artifacts = dict.get(scope, "artifacts")
    if not _sorted_unique(artifacts, _is_hex64):
        return None
    if series is None and not artifacts:
        return None
    return scope


def _activation_or_none(activation: object) -> dict[str, Any] | None:
    """`activation` itself when it is a valid trigger, else `None`.

    `{modes, fixed_date, successor_ids}` (§18.2). `modes` is non-empty,
    sorted and duplicate-free; a non-null `fixed_date` REQUIRES `"fixed-date"`
    among the modes; `successor_ids` may be empty. Mode values are not
    restricted to the registered three: an unregistered mode contributes
    nothing to activation, exactly as the reserved `heartbeat-absence` does,
    and rejecting the document over it would make a later registration
    retroactively invalidate grants that predate it."""
    if not isinstance(activation, dict) or set(dict.keys(activation)) != _ACTIVATION_MEMBERS:
        return None
    modes = dict.get(activation, "modes")
    if not modes or not _sorted_unique(modes, _is_non_empty_str):
        return None
    fixed_date = dict.get(activation, "fixed_date")
    if fixed_date is not None:
        if not transfer._valid_utc_timestamp(fixed_date):
            return None
        if MODE_FIXED_DATE not in modes:
            return None
    if not _sorted_unique(dict.get(activation, "successor_ids"), _is_dns_name):
        return None
    return activation


def _valid_grant_shape(document: object) -> bool:
    """The closed eleven-member shape of §18.2, checked before any
    cryptographic work. `permissions` values are open for the same reason
    `activation.modes` values are (see `_activation_or_none`), but the array
    MUST contain `deliver-to-holder`: a grant that does not deliver to the
    holder is not a sunset grant."""
    if not isinstance(document, dict) or set(dict.keys(document)) != _GRANT_MEMBERS:
        return False
    version = dict.get(document, "grant_version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or not 1 <= version <= _MAX_JCS_INTEGER
    ):
        return False
    permissions = dict.get(document, "permissions")
    return (
        _is_dns_name(dict.get(document, "publisher"))
        and _scope_or_none(dict.get(document, "scope")) is not None
        and _sorted_unique(permissions, _is_non_empty_str)
        and PERMISSION_DELIVER_TO_HOLDER in cast(list[Any], permissions)
        and _activation_or_none(dict.get(document, "activation")) is not None
        and isinstance(dict.get(document, "unprotected_build"), bool)
        # §18.2 types this "string, non-empty", and the emptiness is the
        # load-bearing half rather than tidiness: the prose is the only thing
        # that says what the permission MEANS as an undertaking, so a grant
        # pointing at nowhere would authenticate a promise with no content and
        # could go on to reach `activated`.
        and _is_non_empty_str(dict.get(document, "legal_text_uri"))
        and _is_hex64(dict.get(document, "legal_text_sha256"))
        and _is_non_empty_str(dict.get(document, "jurisdiction"))
        and transfer._valid_utc_timestamp(dict.get(document, "issued_at"))
        and isinstance(dict.get(document, "signature"), dict)
    )


def _valid_declaration_shape(declaration: object) -> bool:
    """The closed four-member shape of §18.4."""
    if not isinstance(declaration, dict) or set(dict.keys(declaration)) != _DECLARATION_MEMBERS:
        return False
    return (
        _is_dns_name(dict.get(declaration, "publisher"))
        and _scope_or_none(dict.get(declaration, "scope")) is not None
        and transfer._valid_utc_timestamp(dict.get(declaration, "declared_at"))
        and isinstance(dict.get(declaration, "signature"), dict)
    )


# --- building ----------------------------------------------------------------


def build_grant(
    grant_version: int,
    publisher: str,
    scope: dict[str, Any],
    permissions: list[str],
    activation: dict[str, Any],
    unprotected_build: bool,
    legal_text_uri: str,
    legal_text_sha256: str,
    jurisdiction: str,
    issued_at: str,
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str,
) -> dict[str, Any]:
    """Build a publisher-signed sunset grant (§18.2), eleven members.

    `signing_kp` mirrors `manifests.build_key_manifest`/`revocation.build_record`
    /`transfer.build_record`: a `pq.HybridSigningKeys` produces a `signature`
    block carrying both the Ed25519 `sig` leg and the `sig_ml_dsa_65` leg (see
    `manifests.sign_signature_block`); a plain `keys.SigningKeyPair` keeps the
    Ed25519-only shape, which a hybrid-keyed publisher's manifest entry will
    then refuse under the §13 AND-rule.

    Like its two siblings, this builder does NOT validate the body it signs:
    building a deliberately malformed document is how the verification side
    gets tested, and a document that does not conform simply never
    authenticates.
    """
    body: dict[str, Any] = {
        "grant_version": grant_version,
        "publisher": publisher,
        "scope": scope,
        "permissions": permissions,
        "activation": activation,
        "unprotected_build": unprotected_build,
        "legal_text_uri": legal_text_uri,
        "legal_text_sha256": legal_text_sha256,
        "jurisdiction": jurisdiction,
        "issued_at": issued_at,
    }
    body["signature"] = manifests.sign_signature_block(canon.canonical_bytes(body), signing_kp, kid)
    return body


def build_declaration(
    publisher: str,
    scope: dict[str, Any],
    declared_at: str,
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    kid: str,
) -> dict[str, Any]:
    """Build a signed cessation declaration (§18.4), four members.

    The signer is the publisher OR a domain listed in the effective grant's
    `activation.successor_ids` — a distinction this builder cannot make (it
    has no grant in hand) and `declaration_signer_role` does.
    """
    record: dict[str, Any] = {
        "publisher": publisher,
        "scope": scope,
        "declared_at": declared_at,
    }
    record["signature"] = manifests.sign_signature_block(
        canon.canonical_bytes(record), signing_kp, kid
    )
    return record


# --- hashing -----------------------------------------------------------------


def grant_hash(document: dict[str, Any]) -> str:
    """`SHA-256(JCS(grant))`, 64 lowercase hex — the ENTIRE signed grant,
    INCLUDING its own `signature` member (unlike the body-only bytes the
    signature itself is computed over).

    This is what `license.preservation_pledge.grant_sha256` commits to
    (§18.2): the SAME `canon.canonical_bytes` this module already uses to
    build and verify the signature — one canonical form, reused, never a
    second one invented for the binding. Mirrors `revocation.record_hash` and
    `transfer.record_hash` exactly.
    """
    return hashlib.sha256(canon.canonical_bytes(document)).hexdigest()


def declaration_hash(declaration: dict[str, Any]) -> str:
    """`SHA-256(JCS(declaration))`, 64 lowercase hex — the ENTIRE signed
    declaration, its own `signature` member included.

    This is what a `cessation-declaration` transparency-log entry commits to
    (§8, the fifth entry type). Logging a declaration is RECOMMENDED and never
    load-bearing: an authenticated declaration activates a grant whether or
    not it was ever logged, the opposite posture from `transfer-record`.
    """
    return hashlib.sha256(canon.canonical_bytes(declaration)).hexdigest()


# --- authentication ----------------------------------------------------------


def _verify_signed_document(
    document: dict[str, Any], key_manifest: dict[str, Any], timestamp_member: str
) -> bool:
    """The half §18.2's authentication paragraph shares with v0.1 §12.1 and
    §17.1: the signer key must be **active** in `key_manifest`, its
    `[valid_from, valid_to]` window must cover the document's OWN signed time
    (never the verifier's clock), and the signature must verify over
    `JCS(document)` with `signature` removed, under the §13 AND-rule."""
    sig_block = cast(dict[str, Any], dict.get(document, "signature"))
    entry = manifests.find_key(key_manifest, dict.get(sig_block, "kid", ""))
    if entry is None or dict.get(entry, "status") != _ACTIVE:
        return False
    signed_at = transfer._parse_date(cast(str, dict.get(document, timestamp_member)))
    if signed_at < transfer._parse_date(cast(str, dict.get(entry, "valid_from"))):
        return False
    valid_to = dict.get(entry, "valid_to")
    if valid_to is not None and signed_at > transfer._parse_date(valid_to):
        return False
    body = {key: value for key, value in dict.items(document) if key != "signature"}
    return manifests.verify_signature_block(canon.canonical_bytes(body), sig_block, entry)


def verify_grant_signature(document: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify a grant's own signature against an ALREADY self-verified
    `key_manifest` — exactly `verify_grant` minus the
    `manifests.verify_key_manifest` self-consistency check, mirroring
    `revocation.verify_record_signature`/`transfer.verify_record_signature`.

    The closed eleven-member shape is checked FIRST: a document whose
    signature happens to verify over a malformed member (any string
    canonicalizes fine, so the signature alone cannot catch this) is still
    rejected. Fails closed on every malformed/wrong-typed/unsigned/
    out-of-window input — never raises.

    This is AUTHENTICATION only. The triple domain binding of §18.4 step 5 —
    `grant.publisher` equal to the resolving manifest's `issuer` equal to the
    receipt's `work.publisher_id` — is a SEPARATE check, because §18.4 reports
    its failure differently (`grant_trust: "signer_mismatch"` with
    `grant_signer_not_publisher`, rather than a plain rejection). Compose it
    from `signer_domain` and the two documents.

    PRECONDITION: the caller has already established
    `manifests.verify_key_manifest(key_manifest)`. Callers checking many
    documents against ONE manifest hoist that call out of their loop.
    """
    try:
        if not _valid_grant_shape(document):
            return False
        return _verify_signed_document(document, key_manifest, "issued_at")
    except Exception:  # see the never-raise note on `signer_domain`
        return False


def verify_grant(document: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify a grant against `key_manifest`, mirroring `revocation.verify_record`
    exactly: the signer key must be **active** in a SELF-CONSISTENT
    `key_manifest`, with its validity window covering the grant's own
    `issued_at`, and the signature must verify under the §13 AND-rule.

    Defense-in-depth: `key_manifest` itself must be self-consistent, so a
    fabricated publisher manifest paired with a matching fabricated grant
    signature cannot verify. Fails closed on every malformed input, never
    raises.
    """
    try:
        return manifests.verify_key_manifest(key_manifest) and verify_grant_signature(
            document, key_manifest
        )
    except Exception:  # see the never-raise note on `signer_domain`
        return False


def verify_declaration_signature(declaration: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """`verify_grant_signature` for a cessation declaration: the closed
    four-member shape, then the same active-key/window/AND-rule checks, with
    the window checked against the declaration's own `declared_at`.

    Authentication only — whether this signer was ENTITLED to declare
    cessation for a given grant is `declaration_signer_role`, and whether the
    declaration reaches that grant's scope is `declaration_covers_grant`.
    """
    try:
        if not _valid_declaration_shape(declaration):
            return False
        return _verify_signed_document(declaration, key_manifest, "declared_at")
    except Exception:  # see the never-raise note on `signer_domain`
        return False


def verify_declaration(declaration: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """`verify_grant` for a cessation declaration: self-consistent manifest
    plus `verify_declaration_signature`. Fails closed, never raises."""
    try:
        return manifests.verify_key_manifest(key_manifest) and verify_declaration_signature(
            declaration, key_manifest
        )
    except Exception:  # see the never-raise note on `signer_domain`
        return False


# --- who signed, and who was entitled to (§18.1, §18.4) ----------------------


def signer_domain(document: object) -> str | None:
    """The signing domain of a grant or declaration: the text before the first
    `/` of `signature.kid` (v0.1 §7.1's kid grammar, where that prefix MUST
    equal the manifest's own `issuer`), or `None` when it is absent,
    wrong-typed, or not a lowercase DNS name.

    §18.1's resolution rule and §18.4 step 5's triple binding are both stated
    over this domain; returning it rather than deciding either keeps the two
    distinguishable, which is what lets a caller report `signer_mismatch`
    separately from a plain authentication failure.
    """
    # Own-item reads (`dict.get(d, k)`), never `d.get(k)`: this resolves a
    # signer from a document supplied on a caller's evidence rail BEFORE
    # anything has authenticated it, so an overridden `get` must not be able
    # to lie about the signer nor to raise out of a resolution both §18.4 and
    # §20.4 perform on untrusted bytes. The enclosing guard covers the
    # triggers an own-item read does not reach (`__getitem__`, `__iter__`,
    # `__eq__`) — the two-part form `authority.entry_for_issuer` documents,
    # and the form every never-raise surface in this module now uses.
    try:
        if not isinstance(document, dict):
            return None
        sig_block = dict.get(document, "signature")
        if not isinstance(sig_block, dict):
            return None
        kid = dict.get(sig_block, "kid")
        if not isinstance(kid, str):
            return None
        domain = kid.split("/", 1)[0]
        return domain if _is_dns_name(domain) else None
    except Exception:
        return None


def declaration_signer_role(declaration: object, document: object) -> str | None:
    """Who may sign (§18.4): `SIGNER_ROLE_PUBLISHER` when the declaration's
    `kid` domain equals the EFFECTIVE grant's `publisher`,
    `SIGNER_ROLE_SUCCESSOR` when it is one of that grant's
    `activation.successor_ids`, and `None` for anyone else — a declaration
    from a stranger is never honored.

    The role is returned rather than a bare boolean because a successor's
    declaration activates the grant AND is reported as such
    (`grant_activated_by_successor`): informational, never a downgrade. The
    successor list is read from the EFFECTIVE grant, so a later version that
    widened it widens who may declare, and one that narrowed it never became
    effective (§18.3).
    """
    try:
        domain = signer_domain(declaration)
        if domain is None or not isinstance(document, dict):
            return None
        publisher = dict.get(document, "publisher")
        if _is_dns_name(publisher) and domain == publisher:
            return SIGNER_ROLE_PUBLISHER
        activation = dict.get(document, "activation")
        successor_ids = (
            dict.get(activation, "successor_ids") if isinstance(activation, dict) else None
        )
        if isinstance(successor_ids, list) and any(domain == entry for entry in successor_ids):
            return SIGNER_ROLE_SUCCESSOR
        return None
    except Exception:  # see the never-raise note on `signer_domain`
        return None


# --- the two coverage predicates (§18.4) -------------------------------------
#
# Written separately, and deliberately not in terms of one another. A
# declaration and a grant are two documents of the SAME shape written by the
# same party, so series equality is a conjunct there; a grant and a receipt are
# not, and the receipt's `work` block is older and looser, so series equality
# is a SUFFICIENT clause here. Folding them into one helper would collapse
# exactly the distinction §18.4 spends a paragraph drawing.


def declaration_covers_grant(declaration: object, document: object) -> bool:
    """DECLARATION coverage (§18.4): a declaration covers a grant iff
    `publisher` is equal, `scope.artifact_series` is equal (both `null` counts
    as equal), and the declaration's `scope.artifacts` is a SUPERSET of the
    grant's. Set containment over sorted, duplicate-free hex arrays — no
    ambiguity left for two implementations to drift apart on.

    Fails closed on every malformed input, never raises: a declaration that
    does not cover is simply not honored.
    """
    try:
        if not isinstance(declaration, dict) or not isinstance(document, dict):
            return False
        declaration_scope = _scope_or_none(dict.get(declaration, "scope"))
        grant_scope = _scope_or_none(dict.get(document, "scope"))
        if declaration_scope is None or grant_scope is None:
            return False
        publisher = dict.get(declaration, "publisher")
        if not _is_dns_name(publisher) or publisher != dict.get(document, "publisher"):
            return False
        if declaration_scope["artifact_series"] != grant_scope["artifact_series"]:
            return False
        return set(grant_scope["artifacts"]) <= set(declaration_scope["artifacts"])
    except Exception:  # see the never-raise note on `signer_domain`
        return False


def grant_covers_receipt(document: object, payload: object) -> bool:
    """GRANT coverage (§18.4), a DIFFERENT predicate from the one above: a
    grant covers a receipt iff EITHER holds —

    - `grant.scope.artifact_series` is non-null and equal to the receipt's
      `work.artifact_series`; OR
    - the receipt's `work.artifacts[]` is PRESENT AND NON-EMPTY, and every
      `sha256` in it appears in `grant.scope.artifacts`.

    Either alone suffices: a grant scoped purely by artifact hash
    (`artifact_series: null`) covers a receipt that names exactly those
    artifacts EVEN IF that receipt also carries a series the grant does not
    name — requiring the series to match here, as declaration coverage does,
    would deny a buyer a grant that demonstrably names their own files.

    The non-empty requirement in the second clause is load-bearing, not
    defensive prose. Both `work.artifact_series` and `work.artifacts` are
    individually optional (v0.1 §5.4), so a receipt may carry only the series;
    stated as a bare universal quantifier, the second clause would then range
    over an empty set and be VACUOUSLY TRUE, making every grant cover every
    series-only receipt — a false `activated` produced by a quantifier rather
    than by any bad evidence, which is the exact direction §18.4's failure
    asymmetry forbids. An empty or absent artifact list is covered by nothing.

    A receipt carrying only a series the grant does not name is uncovered: a
    series is NOT resolved into hashes here, because that resolution depends
    on evidence outside the receipt, and reaching further to say `activated`
    is exactly what §18.4 forbids. Fails closed, never raises.
    """
    try:
        if not isinstance(document, dict) or not isinstance(payload, dict):
            return False
        scope = _scope_or_none(dict.get(document, "scope"))
        if scope is None:
            return False
        work = payload.get("work")
        if not isinstance(work, dict):
            return False

        series = scope["artifact_series"]
        if series is not None and series == work.get("artifact_series"):
            return True

        artifacts = work.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            return False
        granted = set(scope["artifacts"])
        for item in artifacts:
            if not isinstance(item, dict):
                return False
            digest = item.get("sha256")
            if not _is_hex64(digest) or digest not in granted:
                return False
        return True
    except Exception:  # see the never-raise note on `signer_domain`
        return False


# --- the floor-relative ratchet (§18.3) --------------------------------------


def _series_non_narrowing(floor_series: Any, later_series: Any) -> bool:
    """`scope.artifact_series` unchanged, or newly set from `null`. A series
    dropped back to `null`, or swapped for a different one, narrows: the
    buyer's own catalogue would stop being named."""
    return floor_series is None or later_series == floor_series


def _fixed_date_non_narrowing(floor_date: Any, later_date: Any) -> bool:
    """`activation.fixed_date` equal or EARLIER, or newly set from `null`.

    Pushing the backstop date further out makes activation strictly harder to
    reach for a buyer who has already paid, so it narrows even though nothing
    about the permissions changed — and removing the date altogether is that
    same move taken to its limit, so it narrows too.
    """
    if floor_date is None:
        return True
    if later_date is None:
        return False
    return transfer._parse_date(later_date) <= transfer._parse_date(floor_date)


def is_non_narrowing(floor: object, later: object) -> bool:
    """The non-narrowing half of §18.3's ratchet, evaluated against the FLOOR —
    never against another later version, and never against whichever version a
    caller happened to accept first, so the outcome does not depend on the
    order `later_grants` is presented in.

    Relative to the floor, ALL of: `permissions` a superset;
    `scope.artifact_series` unchanged (or newly set from `null`);
    `scope.artifacts` a superset; `unprotected_build` never going from `true`
    to `false`; `activation.modes` a superset; `activation.fixed_date` equal or
    earlier (or newly set from `null`); `activation.successor_ids` a superset.

    The `activation` half is what keeps the trigger from being narrowed after
    the sale. `legal_text_uri`, `legal_text_sha256` and `jurisdiction` are
    deliberately OUTSIDE this test — a verifier cannot read prose and MUST NOT
    pretend to, so two grants differing only in `legal_text_sha256` are simply
    different to a machine, and no comparison of hashes tells a clarification
    from a restriction. That omission leaves the buyer exposed to nothing,
    because the prose that binds them stays the floor's either way; the
    divergence is reported instead, by `prose_differs`.

    This is criterion 2 PLUS the one half of criterion 1 that needs nothing
    but the two documents: `publisher` equality. §18.3 states that equality as
    a precondition of ADMISSIBILITY rather than as a narrowing test, and it is
    enforced here rather than left to the caller because it is load-bearing and
    free: `publisher` is what declaration coverage compares against (§18.4), so
    a later version allowed to change it could move WHO MAY SIGN the cessation
    that opens the grant. A supplied version naming a different publisher is
    not a later version of this grant at all — it is a different grant, and it
    is ignored. A caller holding only this predicate must not be able to widen
    a grant into someone else's hands.

    The REST of criterion 1 — a strictly greater `grant_version`, a signer key
    still active in the publisher's manifest chain, and the
    rollback-or-equivocation rejection of two authenticated grants sharing one
    `grant_version` — needs the manifest chain in hand and belongs with the
    evaluation that resolves it (`evaluate_grant`).

    Fails closed on every malformed input, never raises: a version that cannot
    be compared is ignored, which leaves the floor effective.
    """
    try:
        if not isinstance(floor, dict) or not isinstance(later, dict):
            return False
        floor_publisher, later_publisher = (
            dict.get(floor, "publisher"),
            dict.get(later, "publisher"),
        )
        if not _is_dns_name(floor_publisher) or floor_publisher != later_publisher:
            return False
        floor_scope = _scope_or_none(dict.get(floor, "scope"))
        later_scope = _scope_or_none(dict.get(later, "scope"))
        if floor_scope is None or later_scope is None:
            return False
        floor_activation = _activation_or_none(dict.get(floor, "activation"))
        later_activation = _activation_or_none(dict.get(later, "activation"))
        if floor_activation is None or later_activation is None:
            return False
        floor_permissions, later_permissions = (
            dict.get(floor, "permissions"),
            dict.get(later, "permissions"),
        )
        if not isinstance(floor_permissions, list) or not isinstance(later_permissions, list):
            return False
        if not _sorted_unique(floor_permissions, _is_non_empty_str) or not _sorted_unique(
            later_permissions, _is_non_empty_str
        ):
            return False
        if not set(floor_permissions) <= set(later_permissions):
            return False

        floor_unprotected = dict.get(floor, "unprotected_build")
        later_unprotected = dict.get(later, "unprotected_build")
        if not isinstance(floor_unprotected, bool) or not isinstance(later_unprotected, bool):
            return False
        if floor_unprotected and not later_unprotected:
            return False

        return (
            _series_non_narrowing(floor_scope["artifact_series"], later_scope["artifact_series"])
            and set(floor_scope["artifacts"]) <= set(later_scope["artifacts"])
            and set(floor_activation["modes"]) <= set(later_activation["modes"])
            and _fixed_date_non_narrowing(
                floor_activation["fixed_date"], later_activation["fixed_date"]
            )
            and set(floor_activation["successor_ids"]) <= set(later_activation["successor_ids"])
        )
    except Exception:  # see the never-raise note on `signer_domain`
        return False


def prose_differs(floor: object, later: object) -> bool:
    """Whether an effective later version's prose-bearing members differ from
    the FLOOR's — `legal_text_uri`, `legal_text_sha256` or `jurisdiction`
    (§18.3). ALL THREE count, the URI included: a document served from a new
    location is a new document to the person who has to go read it, even when
    the hash is unchanged.

    The later version governs the machine-checkable members and does NOT
    replace the prose: the grant text opposable for a receipt remains the one
    whose hash the receipt itself signed at purchase. This predicate exists so
    the divergence can be REPORTED (`grant_legal_text_changed`) rather than
    silently resolved, which is the only reading under which "a publisher can
    widen what was promised and can never narrow it" is true of the whole
    document rather than only of its machine-readable half.

    Two documents that cannot be compared report no divergence; a caller only
    reaches this with two authenticated grants.
    """
    if not isinstance(floor, dict) or not isinstance(later, dict):
        return False
    return any(
        dict.get(floor, member) != dict.get(later, member)
        for member in ("legal_text_uri", "legal_text_sha256", "jurisdiction")
    )


# --- structural ceilings (§18.4) ---------------------------------------------


def _within_ceiling(supplied: object, ceiling: int) -> bool:
    if supplied is None:
        return True
    if not isinstance(supplied, list):
        return False
    return len(supplied) <= ceiling


def within_structural_ceilings(
    later_grants: list[Any] | None, declarations: list[Any] | None
) -> bool:
    """Whether both attacker-supplied arrays are within their COUNT ceilings —
    `_MAX_GRANT_LATER_VERSIONS` and `_MAX_GRANT_DECLARATIONS`, 64 each (§18.4).

    Each element of either array costs a hybrid signature verification, so a
    byte cap alone is not a ceiling, exactly as v0.1 §11.3 and §16.1 already
    require elsewhere. Exceeding either truncates evaluation fail-closed
    toward `not_checked`, never toward `activated`.

    This predicate judges COUNT and nothing else: it never indexes, compares,
    hashes or otherwise inspects an element. That is what lets a caller run it
    BEFORE any signature is verified — and the specification is explicit that
    a check which does not run first is not a ceiling at all. Absent evidence
    (`None`) is within every ceiling; anything that is not an array fails
    closed.
    """
    return _within_ceiling(later_grants, _MAX_GRANT_LATER_VERSIONS) and _within_ceiling(
        declarations, _MAX_GRANT_DECLARATIONS
    )


# --- redemption (§18.7) ------------------------------------------------------


def redemption_message(receipt_id: str, audience: str, nonce: bytes) -> bytes:
    """The audience-bound redemption preimage (§18.7, normative, verbatim):

    `UTF8("Attest-redemption-challenge-v1") || 0x00 || UTF8(receipt_id) ||
    0x00 || UTF8(audience) || 0x00 || nonce`

    `receipt_id` is the receipt's own `payload.receipt_id` as UTF-8 text, not
    decoded and re-encoded (v0.1 §8.2 and §17.1 discipline, unchanged);
    `audience` is the custodian's lowercase DNS domain, as UTF-8 text; `nonce`
    is at least 16 RAW bytes, freshly generated by the custodian per challenge.

    `audience` is why this is a NEW preimage rather than a reuse of v0.1
    §8.2's binding challenge: that one names no recipient, so a response
    produced for one custodian would be replayable at another.

    Raises `ValueError` on a nonce below the floor — a caller-side mistake,
    the same posture `commitment.challenge_message` takes. Verification of an
    untrusted response never raises; see `verify_redemption`.
    """
    if len(nonce) < _MIN_REDEMPTION_NONCE_BYTES:
        raise ValueError(f"nonce must be at least {_MIN_REDEMPTION_NONCE_BYTES} bytes")
    return (
        LABEL_REDEMPTION_CHALLENGE
        + b"\x00"
        + receipt_id.encode()
        + b"\x00"
        + audience.encode()
        + b"\x00"
        + nonce
    )


def sign_redemption(
    receipt_id: str, audience: str, nonce: bytes, holder_kp: keys.SigningKeyPair
) -> bytes:
    """The HOLDER's raw 64-byte Ed25519 signature over `redemption_message(...)`.

    `holder_kp` is the receipt's own `buyer.pubkey` keypair — the holder is
    not a manifest signer, so there is no `kid` here, unlike every
    publisher-signed side-document. The classical leg is an
    authorization-liveness mechanism, not the grant's long-term evidentiary
    wrapper: a post-CRQC forger of THIS leg still cannot forge the publisher's
    hybrid signature over the grant, so the holder leg's classical weakness is
    bounded by what surrounds it and is never load-bearing alone.
    """
    return keys.sign(redemption_message(receipt_id, audience, nonce), holder_kp)


def verify_redemption(
    receipt_id: str, audience: str, nonce: bytes, sig: bytes, holder_pubkey_b64u: str
) -> bool:
    """Verify a holder's redemption response for THIS `audience`.

    `holder_pubkey_b64u` is the receipt's own `buyer.pubkey` as its base64url
    text, read by the caller and never by this function. A response produced
    for a different custodian, a different receipt, or a different nonce does
    not verify — that binding is the whole point of the preimage.

    Fails closed and never raises on every malformed input: a wrong-length
    signature or key, a non-base64url key, a short nonce, or a genuinely wrong
    signature all return `False`. A gate that fronts the delivery of content
    must not have an error path that is distinguishable from a rejection.

    Salt disclosure is NOT accepted as a redemption proof anywhere in this
    module, and §18.7 prohibits it normatively: it is a replayable bearer
    proof that also hands over the identifier (v0.1 §8.1) and burns the
    receipt's binding secrecy toward that verifier — unfit for a gate queried
    repeatedly by different custodians.
    """
    try:
        message = redemption_message(receipt_id, audience, nonce)
        return keys.verify_strict(message, sig, keys.b64u_decode(holder_pubkey_b64u))
    except Exception:  # see the never-raise note on `signer_domain`
        return False
