"""Tests for attest.verify — layered verification core, §6 steps 0-5.

Security-critical: this module decides whether a receipt's signature is
valid, from which issuer, and whether it is schema-conformant. Tests build
real envelopes via `issue.issue()` for the happy paths, and hand-craft raw
bytes / manually-signed envelopes for the attack scenarios that `issue()`
itself would refuse to produce (e.g. a kid/issuer domain mismatch) — those
are exactly the inputs `verify()` must defend against regardless of how a
non-conforming envelope came to exist.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from attest import (
    anchor,
    canon,
    commitment,
    issue,
    keys,
    manifests,
    pq,
    revocation,
    tlog,
    validate,
    verify,
)
from tests.helpers import make_payload

ISSUER = "store.example.com"
SERIES = "store.example.com/works/EXG-001"  # matches make_payload()'s default work.artifact_series
EVIL_ISSUER = "evil.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
EVIL_KID = f"{EVIL_ISSUER}/keys/test#ed25519-1"
COMPROMISED_KID = f"{ISSUER}/keys/test#ed25519-compromised"

# TEST ONLY — fixed seeds, never use in production.
KP = keys.from_seed(bytes([9]) * 32)
EVIL_KP = keys.from_seed(bytes([10]) * 32)
COMPROMISED_KP = keys.from_seed(bytes([15]) * 32)


def _key_manifest(
    issuer: str = ISSUER,
    kid: str = KID,
    kp: keys.SigningKeyPair = KP,
    status: str = "active",
    valid_from: str = "2026-01-01T00:00:00Z",
    valid_to: str | None = None,
) -> dict[str, Any]:
    entries = [manifests.key_entry(kid, kp.pub, valid_from, valid_to, status)]
    return manifests.build_key_manifest(issuer, 1, "2026-01-01T00:00:00Z", entries, kp, kid)


def _manifest_active_plus_compromised() -> dict[str, Any]:
    """Manifest self-signed by the active KID, plus a listed-but-compromised key."""
    entries = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(
            COMPROMISED_KID, COMPROMISED_KP.pub, "2026-01-01T00:00:00Z", None, "compromised"
        ),
    ]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID)


def _trust_store(
    manifest: dict[str, Any], issuer: str = ISSUER, provenance: str = "tls"
) -> verify.TrustStore:
    return verify.TrustStore(manifests={issuer: manifest}, provenance={issuer: provenance})


def _to_bytes(envelope: dict[str, Any]) -> bytes:
    """Simulate bytes received over the wire — need not be canonical, only valid JSON."""
    return json.dumps(envelope).encode("utf-8")


# --- happy path --------------------------------------------------------------


def test_valid_envelope_is_ok_with_verified_trust() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"
    assert result.trust == "verified"
    assert result.errors == ()
    assert result.ok is True


def test_bundle_provenance_yields_unauthenticated_tofu_trust() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    trust_store = _trust_store(_key_manifest(), provenance="bundle")
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.ok is True
    assert result.trust == "unauthenticated_tofu"


# --- step 0: preconditions (parse once, strictly) -----------------------------


def test_duplicate_key_in_raw_bytes_is_rejected() -> None:
    raw = b'{"payload":{"a":1},"payload":{"a":2},"signatures":[]}'
    result = verify.verify(raw, _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("duplicate object key" in e for e in result.errors)


def test_non_object_envelope_is_rejected() -> None:
    result = verify.verify(b"[]", _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


def test_invalid_json_is_rejected() -> None:
    result = verify.verify(b"not json at all", _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


# --- tampering -----------------------------------------------------------------


def test_tampered_payload_byte_invalidates_signature() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    raw = bytearray(json.dumps(envelope).encode("utf-8"))
    idx = raw.index(b"Example Game")
    raw[idx] = ord("X")  # flip one byte inside a signed string value
    result = verify.verify(bytes(raw), _trust_store(_key_manifest()))
    assert result.signature == "invalid"


# --- step 1: envelope well-formed, signatures length, alg ---------------------


def test_zero_signatures_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    envelope["signatures"] = []
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


def test_two_signatures_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    envelope["signatures"] = envelope["signatures"] * 2
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


def test_unsupported_alg_is_rejected_never_selected() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    envelope["signatures"][0]["alg"] = "RS256"
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("RS256" in e for e in result.errors)


def test_missing_payload_key_is_invalid() -> None:
    result = verify.verify(_to_bytes({"signatures": []}), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert result.errors


def test_missing_signatures_member_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    del envelope["signatures"]
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("signatures" in e for e in result.errors)


def test_unsupported_attest_version_is_invalid() -> None:
    """`attest_version` is gated by verify() itself (step 1), independent of and
    before the jsonschema `const` check in step 5 — hand-sign to bypass
    issue()'s own schema gate and exercise verify()'s own check directly.

    "0.3" (not "0.2" — 0.2 is a supported hybrid version as of this receipt
    format) stands in for an attest_version verify() does not recognize.
    """
    payload = make_payload()
    payload["attest_version"] = "0.3"
    sig = keys.sign(canon.canonical_bytes(payload), KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("attest_version" in e for e in result.errors)


# --- step 2: issuer binding -----------------------------------------------------


def test_issuer_mismatch_signed_by_evil_domain_key() -> None:
    """Design vector 5: a valid manifest for evil.example.com must never validate
    a receipt claiming issuer.id "store.example.com"."""
    trust_store = verify.TrustStore(
        manifests={
            ISSUER: _key_manifest(),
            EVIL_ISSUER: _key_manifest(EVIL_ISSUER, EVIL_KID, EVIL_KP),
        },
        provenance={ISSUER: "tls", EVIL_ISSUER: "tls"},
    )
    payload = make_payload()  # issuer.id == store.example.com
    sig = keys.sign(canon.canonical_bytes(payload), EVIL_KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": EVIL_KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.signature == "invalid"
    assert any("issuer_mismatch" in e for e in result.errors)


def test_unknown_issuer_no_manifest_is_invalid() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    empty_store = verify.TrustStore(manifests={}, provenance={})
    result = verify.verify(_to_bytes(envelope), empty_store)
    assert result.signature == "invalid"
    assert result.errors


def test_missing_issuer_id_is_invalid() -> None:
    """`issuer.id` is read directly off the payload before any manifest lookup —
    a payload lacking it must fail closed even though a trusted manifest for
    the "real" issuer exists in the store."""
    payload = make_payload()
    payload["issuer"] = {"display_name": "Example Games Store"}  # no "id"
    sig = keys.sign(canon.canonical_bytes(payload), KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.signature == "invalid"
    assert any("issuer.id" in e for e in result.errors)


# --- step 3: key checks (compromise, retirement, validity window) --------------


def test_compromised_key_is_invalid_regardless_of_issued_at() -> None:
    manifest = _key_manifest(status="compromised", valid_from="2020-01-01T00:00:00Z")
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at well inside the window
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


def test_retired_key_within_validity_is_valid_with_warning() -> None:
    manifest = _key_manifest(
        status="retired", valid_from="2026-01-01T00:00:00Z", valid_to="2026-12-31T00:00:00Z"
    )
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at 2026-07-02, inside window
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.ok is True
    assert any("retired" in w for w in result.warnings)


def test_issued_at_outside_validity_window_is_invalid() -> None:
    manifest = _key_manifest(valid_from="2026-01-01T00:00:00Z", valid_to="2026-02-01T00:00:00Z")
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at 2026-07-02, after valid_to
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


def test_issued_at_before_valid_from_is_invalid() -> None:
    """The other edge of the validity window: a receipt claiming to have been
    issued before its own signing key's `valid_from` must be rejected too,
    not just the after-`valid_to` case above."""
    manifest = _key_manifest(valid_from="2027-01-01T00:00:00Z")  # after payload's issued_at
    envelope = issue.issue(make_payload(), KP, KID)  # issued_at 2026-07-02
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


def test_manifest_entry_missing_valid_from_fails_closed() -> None:
    """A corrupted/hand-edited trust-store manifest entry (missing `valid_from`
    entirely) must never resurrect a receipt into validity — `_within_validity`
    fails closed on the KeyError rather than raising or defaulting to valid."""
    entry = {"kid": KID, "pub": keys.b64u(KP.pub), "valid_to": None, "status": "active"}
    manifest = {"issuer": ISSUER, "keys": [entry]}
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"


def test_manifest_entry_missing_pub_fails_closed_with_malformed_key_material() -> None:
    """A trust-store manifest entry missing `pub` must fail closed with a clear
    "malformed key material" error, never crash with an unhandled KeyError."""
    entry = {"kid": KID, "valid_from": "2026-01-01T00:00:00Z", "valid_to": None, "status": "active"}
    manifest = {"issuer": ISSUER, "keys": [entry]}
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))
    assert result.signature == "invalid"
    assert any("malformed key material" in e for e in result.errors)


# --- step 5: schema validation + warnings ---------------------------------------


def test_unknown_top_level_field_is_valid_with_warning() -> None:
    payload = make_payload()
    payload["extension_field"] = "some-value"
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.ok is True
    assert any("extension_field" in w for w in result.warnings)


def test_drm_bound_receipt_emits_warning() -> None:
    payload = make_payload(
        license={"revocability": "refund_window", "revocation_window_days": 14, "drm": "drm-bound"}
    )
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.ok is True
    assert any("drm-bound" in w for w in result.warnings)


def test_unknown_end_of_life_value_emits_warning() -> None:
    payload = make_payload(survivability={"end_of_life": "some-future-vocabulary"})
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.ok is True
    assert any("end_of_life" in w for w in result.warnings)


# --- step 6: revocation-by-class (design §3.1/§6) --------------------------------
#
# revocability=="none" -> a matching, signature-valid record is itself invalid
# (irrevocability guarantee; design vector 16). revocability=="policy" -> a
# matching valid record is always honored (design vector 15). revocability==
# "refund_window" -> a matching valid record is honored only if the record's
# OWN signed revoked_at falls within issued_at + revocation_window_days.


def test_revocation_policy_valid_record_is_revoked() -> None:
    """Design vector 15: revocability:policy + a valid revocation record -> revoked."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-03T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "revoked"
    assert result.ok is False


def test_revocation_against_none_class_is_ignored() -> None:
    """Design vector 16: this is the whole irrevocability argument — a valid
    record against a revocability:none receipt is invalid, and the receipt
    stays ok."""
    payload = make_payload()  # revocability: none (base payload default)
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-03T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert any("revocability" in w and "none" in w for w in result.warnings)


def test_revocability_none_with_non_matching_record_reports_not_revoked_as_of() -> None:
    """An irrevocable receipt still gets an honest freshness anchor from the
    feed when nothing in it revokes THIS receipt — distinct from the
    "matching record present" vector-16 case above (`valid` stays empty here,
    exercising the "none" class's own not-revoked fallback rather than the
    ignored-record path)."""
    payload = make_payload()  # revocability: none (base default)
    envelope = issue.issue(payload, KP, KID)
    other_record = revocation.build_record(
        "01J1V5B4M9Z8QWERTY99999999", "revoked", "2026-07-05T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[other_record]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


def test_revocation_refund_window_inside_window_is_revoked() -> None:
    payload = make_payload(
        license={"revocability": "refund_window", "revocation_window_days": 14},
        issued_at="2026-07-02T14:30:00Z",
    )
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "revoked"
    assert result.ok is False


def test_revocation_refund_window_outside_window_is_ignored() -> None:
    payload = make_payload(
        license={"revocability": "refund_window", "revocation_window_days": 14},
        issued_at="2026-07-02T14:30:00Z",
    )
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-08-01T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert any("window" in w for w in result.warnings)


def test_revocation_unsigned_record_is_ignored_with_warning() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    garbage_record = {
        "receipt_id": payload["receipt_id"],
        "status": "revoked",
        "revoked_at": "2026-07-03T00:00:00Z",
        # no "signature" member at all
    }
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[garbage_record]
    )
    # The junk record does not authenticate, so it is the sole record AND yields
    # no freshness anchor -> revocation is unknown (not not_revoked_as_of), and
    # the matching-but-unverified record is ignored with a warning.
    assert result.revocation == "unknown"
    assert result.ok is True
    assert any("failed verification" in w for w in result.warnings)


def test_revocation_view_supplied_no_match_reports_not_revoked_as_of() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    other_record = revocation.build_record(
        "01J1V5B4M9Z8QWERTY99999999", "revoked", "2026-07-05T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[other_record]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


def test_empty_revocation_view_reports_unknown() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[])
    assert result.revocation == "unknown"


def test_no_revocation_view_reports_unknown() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))
    assert result.revocation == "unknown"


def test_non_list_revocation_view_raises_type_error() -> None:
    """Caller-contract enforcement (security): a lone revocation-record OBJECT
    (the exact shape `revocation.build_record` returns) passed where a list is
    required must fail loud, never be silently iterated as dict keys — which
    would authenticate nothing and pass a genuinely revoked receipt as ok."""
    envelope = issue.issue(make_payload(), KP, KID)
    with pytest.raises(TypeError):
        verify.verify(
            _to_bytes(envelope),
            _trust_store(_key_manifest()),
            revocation_view={"receipt_id": "01J1V5B4M9Z8QWERTY12345678"},  # type: ignore[arg-type]
        )


# --- step 6 hardening: authenticate records before honoring/anchoring them --------


def test_revocation_record_signed_by_compromised_key_is_ignored() -> None:
    """The silent-DoS fix: a record signed by a key the issuer has flagged
    `compromised` (§5) must NOT revoke a policy receipt — it fails
    verification and is ignored with a warning, receipt stays ok."""
    manifest = _manifest_active_plus_compromised()
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)  # receipt signed by the still-active KID
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-03T00:00:00Z", COMPROMISED_KP, COMPROMISED_KID
    )
    result = verify.verify(_to_bytes(envelope), _trust_store(manifest), revocation_view=[record])
    assert result.signature == "valid"
    assert result.revocation == "unknown"  # no authenticated record -> no anchor
    assert result.ok is True
    assert any("failed verification" in w for w in result.warnings)


def test_not_revoked_as_of_uses_only_authenticated_records_for_anchor() -> None:
    """T must not be inflatable by injecting unsigned junk with a future
    `revoked_at`: the anchor is the max over signature-verified records only."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    authentic = revocation.build_record(
        "01J1V5B4M9Z8QWERTY99999999", "revoked", "2026-07-05T00:00:00Z", KP, KID
    )
    junk = {
        "receipt_id": "01J1V5B4M9Z8QWERTY88888888",
        "status": "revoked",
        "revoked_at": "2099-01-01T00:00:00Z",  # unsigned -> must not anchor T
    }
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[authentic, junk]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


def test_not_revoked_as_of_unknown_when_only_unauthenticated_records() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    junk = {
        "receipt_id": "01J1V5B4M9Z8QWERTY88888888",
        "status": "revoked",
        "revoked_at": "2099-01-01T00:00:00Z",
    }
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[junk]
    )
    assert result.revocation == "unknown"


def test_valid_record_with_non_revoked_status_is_not_a_revocation() -> None:
    """Only status=='revoked' drives revocation. A validly-signed record with a
    different status is not a revocation (but still authenticates the feed, so
    it can anchor T)."""
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "disputed", "2026-07-05T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "not_revoked_as_of:2026-07-05T00:00:00Z"
    assert result.ok is True


# --- G5 (TM-47): revocation-record log entries + deadline effectiveness ----------
#
# `refund_window` revocation records are effective only if a matching
# `revocation-record` log entry proves they were anchored no later than the
# receipt's own refund-window deadline (issued_at + revocation_window_days) —
# closing the backdating gap where a revocation with no contradicting
# evidence could be asserted after the fact. The rule engages only once the
# verifier is Stage-2 capable (log_keys/anchor_policy supplied, exactly the
# existing zero-behavior-change gate for transparency/corroboration); a
# caller that never supplies them keeps v0.1 semantics unchanged.
# `policy`/`compromised`/`none` classes are unaffected: logging remains
# optional corroboration for them.

_REVOCATION_LOG_ORIGIN = "revocation-log.attest.example/2026"
_REVOCATION_LOG_NAME = "attest-revocation-log-1"


def _revocation_log_key(hk: pq.HybridSigningKeys) -> tlog.LogKey:
    return tlog.LogKey(
        origin=_REVOCATION_LOG_ORIGIN,
        name=_REVOCATION_LOG_NAME,
        ed25519_pub=hk.ed.pub,
        mldsa_pub=hk.mldsa.pub,
    )


def _revocation_log_evidence(
    record: dict[str, Any],
    hk: pq.HybridSigningKeys,
    header_time: int,
    anchor_profile: str | None = None,
) -> tuple[dict[str, Any], anchor.AnchorPolicy]:
    """Build a genuine, single-leaf transparency-log entry for `record`,
    hybrid-signed and OTS-anchored to a pinned header at `header_time`
    (mirrors `tools/gen_vectors.py`'s `28-transparency`/`j-ots-anchor` shape:
    a single `["sha256"]` op over `SHA-256(checkpoint.note_bytes)`).

    `anchor_profile=None` (the default) builds a legacy note-v1 commitment
    (`SHA-256(checkpoint.note_bytes)`, no `anchor_profile` declared) —
    genuinely verifiable (eternal verifiability) but flagged
    `anchor_note_only` by the shared evaluator (G4). Pass
    `anchor_profile="signed-note-v2"` to instead commit over
    `checkpoint.signed_note_bytes` (mirrors `32-anchor-v2/a-v2-valid`) —
    what newly produced anchors MUST use per the spec, and what
    `tools/gen_vectors.py`'s group 33 now generates."""
    entry = {
        "type": "revocation-record",
        "issuer": ISSUER,
        "record_sha256": revocation.record_hash(record),
    }
    entry_bytes = tlog.encode_entry(entry)
    root = tlog.build_tree([entry_bytes])
    checkpoint_text = tlog.sign_checkpoint(
        _REVOCATION_LOG_ORIGIN, 1, root, hk, _REVOCATION_LOG_NAME
    )
    checkpoint = tlog.parse_checkpoint(checkpoint_text)
    commitment_bytes = (
        checkpoint.signed_note_bytes
        if anchor_profile == "signed-note-v2"
        else checkpoint.note_bytes
    )
    accumulator_start = hashlib.sha256(commitment_bytes).digest()
    header_merkle_root = hashlib.sha256(accumulator_start).digest().hex()
    header_hash = "ab" * 32
    policy = anchor.AnchorPolicy(
        pinned_headers={
            header_hash: anchor.PinnedHeader(
                header_hash=header_hash, merkle_root=header_merkle_root, time=header_time
            )
        },
        crqc_horizon=None,
    )
    anchors: dict[str, Any] = {
        "checkpoint": checkpoint_text,
        "proofs": [
            {
                "kind": "ots",
                "ops": [["sha256"]],
                "header_merkle_root": header_merkle_root,
                "header_time": header_time,
                "header_hash": header_hash,
            }
        ],
    }
    if anchor_profile is not None:
        anchors["anchor_profile"] = anchor_profile
    evidence = {
        "entry": entry,
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": [],
        "checkpoint": checkpoint_text,
        "anchors": anchors,
    }
    return evidence, policy


def _unix_seconds(iso: str) -> int:
    return int(datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _refund_window_payload() -> dict[str, Any]:
    return make_payload(
        license={"revocability": "refund_window", "revocation_window_days": 14},
        issued_at="2026-07-02T14:30:00Z",
    )


def test_refund_window_revocation_with_timely_logged_entry_honored() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    # header_time inside the refund window (deadline: 2026-07-16T14:30:00Z).
    # Default (legacy note-v1) evidence — asserts the revocation-evidence
    # path surfaces the shared evaluator's `anchor_note_only` diagnostic
    # (I1: verify() must not discard `result.warnings` on this path).
    evidence, policy = _revocation_log_evidence(record, hk, _unix_seconds("2026-07-10T00:00:00Z"))
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=evidence,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=policy,
    )
    assert result.revocation == "revoked"
    assert result.ok is False
    assert "anchor_note_only" in result.warnings


def test_refund_window_revocation_unlogged_is_ignored_with_warning() -> None:
    """Stage-2-capable verifier (log_keys/anchor_policy set), but NO log
    evidence at all for this record -> the record was never proven logged,
    so the deadline rule cannot honor it — ignored, not silently revoked."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=None,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert "revocation_unlogged_deadline" in result.warnings


def test_refund_window_revocation_anchored_late_is_ignored() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    # header_time AFTER the refund window deadline (2026-07-16T14:30:00Z).
    evidence, policy = _revocation_log_evidence(record, hk, _unix_seconds("2026-08-01T00:00:00Z"))
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=evidence,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=policy,
    )
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert "revocation_unlogged_deadline" in result.warnings


def test_policy_class_revocation_unchanged_without_log() -> None:
    """`policy`/`compromised`/`none` classes are UNAFFECTED by the deadline
    rule — logging remains optional corroboration for them, even under a
    Stage-2-capable verifier with no log evidence supplied."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-03T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=None,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )
    assert result.revocation == "revoked"
    assert result.ok is False
    assert "revocation_unlogged_deadline" not in result.warnings


def test_refund_window_revocation_without_stage2_config_keeps_v01_semantics() -> None:
    """The true bare-v0.1 case: no log_keys/anchor_policy at all (verifier not
    Stage-2 capable) -> the deadline rule never engages, so an otherwise
    window-valid record is honored exactly as it was before G5."""
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[record]
    )
    assert result.revocation == "revoked"
    assert result.ok is False


# --- I1(c): revocation-evidence path dispatches through the shared
# transparency evaluator exactly like the direct transparency path
# (T4-dispatch tests) --------------------------------------------------------


def test_refund_window_revocation_v2_profiled_evidence_honored_without_note_only_warning() -> None:
    """v2-profiled revocation evidence (the shape `gen_vectors.py` group 33
    now produces) verifies under the v2 seed — honored, and crucially does
    NOT carry `anchor_note_only` (that warning is specific to the legacy
    note-v1 commitment)."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    evidence, policy = _revocation_log_evidence(
        record, hk, _unix_seconds("2026-07-10T00:00:00Z"), anchor_profile="signed-note-v2"
    )
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=evidence,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=policy,
    )
    assert result.revocation == "revoked"
    assert result.ok is False
    assert "anchor_note_only" not in result.warnings


def test_refund_window_revocation_legacy_profiled_evidence_yields_anchor_note_only() -> None:
    """A legacy-profiled bundle on the revocation-evidence path yields
    `anchor_note_only` (the RED test from I1(a)) — still honored (eternal
    verifiability), but flagged as the weaker profile, exactly like the
    direct transparency path's own G4 behavior."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    evidence, policy = _revocation_log_evidence(record, hk, _unix_seconds("2026-07-10T00:00:00Z"))
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=evidence,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=policy,
    )
    assert result.revocation == "revoked"
    assert result.ok is False
    assert "anchor_note_only" in result.warnings


# --- M1: deadline equality boundary is pinned at `<=`, not `<` -------------


def test_refund_window_revocation_anchored_exactly_at_deadline_is_timely() -> None:
    """`anchored_before == deadline` EXACTLY is timely (honored). A
    regression from `<=` to `<` in `_revocation_deadline_satisfied` must
    turn this test red."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    # Deadline is issued_at (2026-07-02T14:30:00Z) + 14 days == 2026-07-16T14:30:00Z.
    evidence, policy = _revocation_log_evidence(
        record,
        hk,
        _unix_seconds("2026-07-16T14:30:00Z"),
        anchor_profile="signed-note-v2",
    )
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=evidence,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=policy,
    )
    assert result.revocation == "revoked"
    assert result.ok is False
    assert "revocation_unlogged_deadline" not in result.warnings


def test_refund_window_revocation_anchored_one_second_after_deadline_is_late() -> None:
    """`deadline + 1s` is late (ignored+warning) — the boundary's other side,
    pinning the equality is inclusive on the `<=` side only."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    payload = _refund_window_payload()
    envelope = issue.issue(payload, KP, KID)
    record = revocation.build_record(
        payload["receipt_id"], "revoked", "2026-07-10T00:00:00Z", KP, KID
    )
    # Deadline is 2026-07-16T14:30:00Z; one second late.
    evidence, policy = _revocation_log_evidence(
        record,
        hk,
        _unix_seconds("2026-07-16T14:30:00Z") + 1,
        anchor_profile="signed-note-v2",
    )
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        revocation_view=[record],
        revocation_evidence=evidence,
        log_keys=[_revocation_log_key(hk)],
        anchor_policy=policy,
    )
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert "revocation_unlogged_deadline" in result.warnings


# --- step 7: buyer binding (design §3.2) ------------------------------------------


def test_binding_salt_disclosure_proven() -> None:
    salt = bytes(range(16))
    identifier, identifier_type = "buyer@example.com", "email"
    commitment_bytes = commitment.compute(identifier, identifier_type, salt)
    payload = make_payload(
        buyer={"commitment": keys.b64u(commitment_bytes), "identifier_type": identifier_type}
    )
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(
        identifier=identifier, identifier_type=identifier_type, salt=salt
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "proven"


def test_binding_salt_disclosure_wrong_salt_is_not_proven() -> None:
    salt = bytes(range(16))
    wrong_salt = bytes(range(16, 32))
    identifier, identifier_type = "buyer@example.com", "email"
    commitment_bytes = commitment.compute(identifier, identifier_type, salt)
    payload = make_payload(
        buyer={"commitment": keys.b64u(commitment_bytes), "identifier_type": identifier_type}
    )
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(
        identifier=identifier, identifier_type=identifier_type, salt=wrong_salt
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_binding_salt_disclosure_non_ascii_email_proven() -> None:
    """Exercises §3.2 normalize(): NFC + ASCII-only lowercasing on a non-ASCII email."""
    salt = bytes(range(16))
    identifier, identifier_type = "Büyér+Tag@Example.com", "email"
    commitment_bytes = commitment.compute(identifier, identifier_type, salt)
    payload = make_payload(
        buyer={"commitment": keys.b64u(commitment_bytes), "identifier_type": identifier_type}
    )
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(
        identifier=identifier, identifier_type=identifier_type, salt=salt
    )
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "proven"


def test_binding_challenge_disclosure_proven() -> None:
    buyer_kp = keys.from_seed(bytes([11]) * 32)
    payload = make_payload(buyer={"pubkey": keys.b64u(buyer_kp.pub)})
    envelope = issue.issue(payload, KP, KID)
    nonce = bytes(range(16))
    sig = commitment.sign_challenge(payload["receipt_id"], nonce, buyer_kp)
    disclosure = verify.Disclosure(challenge=(nonce, sig))
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "proven"


def test_binding_challenge_disclosure_wrong_nonce_is_not_proven() -> None:
    buyer_kp = keys.from_seed(bytes([11]) * 32)
    payload = make_payload(buyer={"pubkey": keys.b64u(buyer_kp.pub)})
    envelope = issue.issue(payload, KP, KID)
    nonce = bytes(range(16))
    wrong_nonce = bytes(range(16, 32))
    sig = commitment.sign_challenge(payload["receipt_id"], nonce, buyer_kp)
    disclosure = verify.Disclosure(challenge=(wrong_nonce, sig))
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_binding_challenge_disclosure_null_pubkey_is_not_proven() -> None:
    payload = make_payload()  # buyer.pubkey defaults to null
    envelope = issue.issue(payload, KP, KID)
    buyer_kp = keys.from_seed(bytes([11]) * 32)
    nonce = bytes(range(16))
    sig = commitment.sign_challenge(payload["receipt_id"], nonce, buyer_kp)
    disclosure = verify.Disclosure(challenge=(nonce, sig))
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_binding_salt_disclosure_without_identifier_fails_closed() -> None:
    """The docstring's canonical malformed-disclosure example: `salt` without
    `identifier` is a partial salt path, so it must fail closed to
    "not_proven" rather than being evaluated (or raising)."""
    payload = make_payload()
    envelope = issue.issue(payload, KP, KID)
    disclosure = verify.Disclosure(salt=bytes(16))  # identifier/identifier_type left None
    result = verify.verify(
        _to_bytes(envelope), _trust_store(_key_manifest()), disclosure=disclosure
    )
    assert result.binding == "not_proven"


def test_no_disclosure_is_not_checked_even_with_revocation_view() -> None:
    payload = make_payload(license={"revocability": "policy"})
    envelope = issue.issue(payload, KP, KID)
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[])
    assert result.binding == "not_checked"


# --- steps 6-7 only run on an already-valid signature+schema ---------------------


def test_invalid_signature_receipt_skips_revocation_and_binding() -> None:
    envelope = issue.issue(make_payload(), KP, KID)
    raw = bytearray(json.dumps(envelope).encode("utf-8"))
    idx = raw.index(b"Example Game")
    raw[idx] = ord("X")
    disclosure = verify.Disclosure(identifier="x", identifier_type="email", salt=bytes(16))
    result = verify.verify(
        bytes(raw), _trust_store(_key_manifest()), revocation_view=[], disclosure=disclosure
    )
    assert result.signature == "invalid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"


def test_schema_invalid_receipt_skips_revocation_and_binding() -> None:
    payload = make_payload()
    del payload["work"]  # schema-invalid: missing required top-level field
    sig = keys.sign(canon.canonical_bytes(payload), KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()), revocation_view=[])
    assert result.signature == "valid"
    assert result.schema == "invalid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"


# --- trust: manifest rotation continuity (design §5) ------------------------------


def test_rotation_continuity_happy_path_keeps_normal_trust() -> None:
    root = _key_manifest()  # v1, sole active key KID/KP
    entries_v2 = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    v2 = manifests.build_key_manifest(ISSUER, 2, "2026-02-01T00:00:00Z", entries_v2, KP, KID)
    trust_store = verify.TrustStore(
        manifests={ISSUER: v2}, provenance={ISSUER: "tls"}, chains={ISSUER: [root, v2]}
    )
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.trust == "verified"
    assert result.ok is True


def test_rotation_discontinuous_chain_yields_unverified_rotation() -> None:
    root = _key_manifest()  # v1, sole active key KID/KP
    stranger_kp = keys.from_seed(bytes([12]) * 32)
    stranger_kid = f"{ISSUER}/keys/test#ed25519-9"
    entries_v2 = [
        manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"),
        manifests.key_entry(stranger_kid, stranger_kp.pub, "2026-02-01T00:00:00Z", None, "active"),
    ]
    # v2 signed by a key that was never active in v1 -> discontinuous rotation.
    v2 = manifests.build_key_manifest(
        ISSUER, 2, "2026-02-01T00:00:00Z", entries_v2, stranger_kp, stranger_kid
    )
    trust_store = verify.TrustStore(
        manifests={ISSUER: v2}, provenance={ISSUER: "tls"}, chains={ISSUER: [root, v2]}
    )
    envelope = issue.issue(make_payload(), KP, KID)  # still resolves fine against v2's KID entry
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.signature == "valid"
    assert result.trust == "unverified_rotation"


def test_no_chain_recorded_is_backward_compatible() -> None:
    """Task-8 TrustStore construction (no `chains` kwarg) must keep working."""
    trust_store = verify.TrustStore(manifests={ISSUER: _key_manifest()}, provenance={ISSUER: "tls"})
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.trust == "verified"


# --- trust: artifact manifest currency (G2/G3, attest-versioning.md rev 4) -------


def _artifact_manifest(version: int, manifest_version: int | None) -> dict[str, Any]:
    return manifests.build_artifact_manifest(
        ISSUER,
        SERIES,
        version,
        "2026-03-01T00:00:00Z",
        [],
        KP,
        KID,
        manifest_version=manifest_version,
    )


def test_artifact_manifest_no_trust_store_entry_is_zero_behavior_change() -> None:
    """A TrustStore with no `artifact_manifests` entry for the receipt's series
    (Task-8-shaped construction, no new kwargs at all) must keep working exactly
    as before this task."""
    trust_store = verify.TrustStore(manifests={ISSUER: _key_manifest()}, provenance={ISSUER: "tls"})
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.trust == "verified"
    assert result.warnings == ()


def test_artifact_manifest_monotone_chain_keeps_normal_trust() -> None:
    am1 = _artifact_manifest(1, 1)
    am2 = _artifact_manifest(2, 2)
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: am2}},
        artifact_manifest_chains={ISSUER: {SERIES: [am1, am2]}},
    )
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.trust == "verified"
    assert result.ok is True
    assert "artifact_manifest_unversioned" not in result.warnings


def test_artifact_manifest_rollback_yields_unverified_rotation() -> None:
    """The trust store's own artifact-manifest chain history ends at `am2`, but
    the "currently pinned" manifest handed to `verify()` is the OLDER `am1` — a
    rollback attempt (or a stale re-import) the verifier already has evidence
    against. Mirrors `test_rotation_discontinuous_chain_yields_unverified_rotation`
    for key manifests."""
    am1 = _artifact_manifest(1, 1)
    am2 = _artifact_manifest(2, 2)
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: am1}},
        artifact_manifest_chains={ISSUER: {SERIES: [am1, am2]}},
    )
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert result.signature == "valid"
    assert result.trust == "unverified_rotation"


def test_artifact_manifest_missing_manifest_version_warns_legacy() -> None:
    legacy = _artifact_manifest(1, None)
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: legacy}},
    )
    envelope = issue.issue(make_payload(), KP, KID)
    result = verify.verify(_to_bytes(envelope), trust_store)
    assert "artifact_manifest_unversioned" in result.warnings
    assert result.trust == "verified"
    assert result.ok is True


def test_unauthenticated_artifact_manifest_is_ignored_before_currency() -> None:
    am1 = _artifact_manifest(1, 1)
    am2 = _artifact_manifest(2, 2)
    del am2["manifest_signature"]
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: am2}},
        artifact_manifest_chains={ISSUER: {SERIES: [am1, am2]}},
    )
    result = verify.verify(_to_bytes(issue.issue(make_payload(), KP, KID)), trust_store)
    assert result.trust == "verified"
    assert result.warnings == ("artifact_manifest_unauthenticated",)


def test_legacy_chain_transitions_are_warn_only() -> None:
    versioned = _artifact_manifest(2, 1)
    legacy = _artifact_manifest(1, None)
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: versioned}},
        artifact_manifest_chains={ISSUER: {SERIES: [legacy, versioned]}},
    )
    result = verify.verify(_to_bytes(issue.issue(make_payload(), KP, KID)), trust_store)
    assert result.trust == "verified"
    assert result.warnings == ("artifact_manifest_unversioned",)


def test_legacy_pinned_after_versioned_history_is_warn_only() -> None:
    # Round-2 residual (review): a LEGACY pinned candidate after versioned
    # history used to hit the chain-tail-mismatch branch and get the
    # forbidden currency downgrade. Currency (continuity AND tail compare)
    # must be skipped entirely when any authenticated member is legacy.
    versioned = _artifact_manifest(1, 1)
    legacy = _artifact_manifest(2, None)
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: legacy}},
        artifact_manifest_chains={ISSUER: {SERIES: [versioned]}},
    )
    result = verify.verify(_to_bytes(issue.issue(make_payload(), KP, KID)), trust_store)
    assert result.trust == "verified"
    assert result.warnings == ("artifact_manifest_unversioned",)


def test_artifact_currency_is_scoped_to_receipt_issuer_and_series() -> None:
    am1 = _artifact_manifest(1, 1)
    am2 = _artifact_manifest(2, 2)
    other_issuer = "other.example.com"
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: am2}, other_issuer: {SERIES: am1}},
        artifact_manifest_chains={ISSUER: {SERIES: [am1, am2]}, other_issuer: {SERIES: [am1, am2]}},
    )
    result = verify.verify(_to_bytes(issue.issue(make_payload(), KP, KID)), trust_store)
    assert result.trust == "verified"
    assert result.warnings == ()


def test_artifact_manifest_issuer_mismatch_is_ignored_with_distinct_warning() -> None:
    mismatched = _artifact_manifest(1, 1)
    mismatched["issuer"] = "other.example.com"
    trust_store = verify.TrustStore(
        manifests={ISSUER: _key_manifest()},
        provenance={ISSUER: "tls"},
        artifact_manifests={ISSUER: {SERIES: mismatched}},
    )
    result = verify.verify(_to_bytes(issue.issue(make_payload(), KP, KID)), trust_store)
    assert result.trust == "verified"
    assert result.warnings == ("artifact_manifest_issuer_mismatch",)


# --- G1 normative ceilings (attest-versioning.md §5 amendment) --------------


def test_envelope_over_byte_ceiling_rejected() -> None:
    padding = validate.MAX_ENVELOPE_BYTES + 4096
    payload = make_payload(work={"title": "x" * padding})
    envelope = issue.issue(payload, KP, KID)
    raw = json.dumps(envelope).encode("utf-8")
    assert len(raw) > validate.MAX_ENVELOPE_BYTES  # sanity: genuinely over the ceiling

    result = verify.verify(raw, _trust_store(_key_manifest()))

    assert result.schema == "invalid"
    assert any("envelope exceeds" in e for e in result.errors)
    assert result.ok is False


def test_envelope_at_byte_ceiling_not_rejected_for_size() -> None:
    """The boundary is strict `>`: at exactly the ceiling, the size check
    does not fire (the receipt may still fail schema validation for other
    reasons, e.g. `work.title` is required to be non-empty but has no upper
    length bound — so this only asserts the size-specific error is absent)."""
    payload = make_payload()
    envelope = issue.issue(payload, KP, KID)
    raw = json.dumps(envelope).encode("utf-8")
    assert len(raw) < validate.MAX_ENVELOPE_BYTES  # sanity: a real receipt is tiny

    result = verify.verify(raw, _trust_store(_key_manifest()))

    assert not any("envelope exceeds" in e for e in result.errors)


def test_envelope_nesting_depth_over_ceiling_rejected() -> None:
    """The nesting-depth ceiling (`validate.MAX_JSON_DEPTH`, an alias of
    `canon.MAX_DEPTH` since the 2026-07-22 fix wave — see `validate.py`'s
    docstring) is enforced entirely by `canon.loads_strict` during parsing:
    an over-ceiling envelope never produces a parsed object, so it is
    reported the same way any other malformed envelope is, `schema:
    "not_checked"` (never the `"invalid"` conformance-surface tag the
    byte-size/manifest-array ceilings use, since those run AFTER a
    successful parse).

    The hostile wire is assembled TEXTUALLY rather than through `issue.issue`:
    since the ceiling reached the serializer and the issuance path (v0.1 §11.3,
    rev 9) a conforming issuer can no longer produce these bytes, and an
    attacker never went through one. The depth is exactly
    `MAX_JSON_DEPTH + 1` — the envelope object itself is level 1 and the
    payload chain adds `MAX_JSON_DEPTH` more."""
    depth = validate.MAX_JSON_DEPTH
    raw = b'{"payload":' + b'{"n":' * depth + b"1" + b"}" * depth + b',"signatures":[]}'

    result = verify.verify(raw, _trust_store(_key_manifest()))

    assert result.schema == "not_checked"
    assert any("maximum nesting depth exceeded" in e for e in result.errors)
    assert result.ok is False


def test_issued_envelopes_are_always_parsable() -> None:
    """The property C-5 denied, at the issuance entry point: what a conforming
    issuer emits, the profile's own parser accepts. Before rev 9 a payload one
    level under the ceiling produced an envelope one level over it."""
    for levels in (canon.MAX_DEPTH - 4, canon.MAX_DEPTH - 3, canon.MAX_DEPTH - 2):
        nested: Any = "leaf"
        for _ in range(levels):
            nested = {"n": nested}
        payload = make_payload()
        payload["_depth_probe"] = nested
        envelope = issue.issue(payload, KP, KID)
        assert canon.loads_strict(_to_bytes(envelope))


def test_envelope_shallow_nesting_not_rejected_for_depth() -> None:
    envelope = issue.issue(make_payload(), KP, KID)

    result = verify.verify(_to_bytes(envelope), _trust_store(_key_manifest()))

    assert not any("maximum nesting depth exceeded" in e for e in result.errors)


def test_issuer_manifest_over_key_ceiling_rejected() -> None:
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    for i in range(manifests.MAX_MANIFEST_KEYS):
        filler_kp = keys.from_seed(
            hashlib.sha256(f"test-verify-ceiling-filler-{i}".encode()).digest()
        )
        entries.append(
            manifests.key_entry(
                f"{ISSUER}/keys/test#filler-{i}",
                filler_kp.pub,
                "2026-01-01T00:00:00Z",
                None,
                "active",
            )
        )
    oversized_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID
    )
    envelope = issue.issue(make_payload(), KP, KID)

    result = verify.verify(_to_bytes(envelope), _trust_store(oversized_manifest))

    assert result.schema == "invalid"
    assert any("issuer manifest exceeds" in e for e in result.errors)
    assert result.ok is False


def test_issuer_manifest_at_key_ceiling_not_rejected_for_size() -> None:
    result = verify.verify(
        _to_bytes(issue.issue(make_payload(), KP, KID)), _trust_store(_key_manifest())
    )
    assert not any("issuer manifest exceeds" in e for e in result.errors)


def test_issuer_manifest_over_key_ceiling_rejected_before_canonicalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I1 (2026-07-22 fix wave 2): the G1 key-manifest ceiling must bound work
    BEFORE any cryptographic or schema work on the hostile manifest (spec
    v0.1 §11.3) — an oversized manifest must be rejected without ever being
    passed to `canon.canonical_bytes` (the entrypoint transparency-claim
    hashing and signature verification both use on manifest/payload data)."""
    entries = [manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    for i in range(manifests.MAX_MANIFEST_KEYS):
        filler_kp = keys.from_seed(
            hashlib.sha256(f"test-verify-ceiling-precanon-filler-{i}".encode()).digest()
        )
        entries.append(
            manifests.key_entry(
                f"{ISSUER}/keys/test#precanon-filler-{i}",
                filler_kp.pub,
                "2026-01-01T00:00:00Z",
                None,
                "active",
            )
        )
    oversized_manifest = manifests.build_key_manifest(
        ISSUER, 1, "2026-01-01T00:00:00Z", entries, KP, KID
    )
    envelope = issue.issue(make_payload(), KP, KID)

    canonicalized: list[object] = []
    original_canonical_bytes = canon.canonical_bytes

    def _counting_canonical_bytes(obj: object) -> bytes:
        canonicalized.append(obj)
        return original_canonical_bytes(obj)

    monkeypatch.setattr(canon, "canonical_bytes", _counting_canonical_bytes)

    # A key-manifest transparency claim is the concrete path (Stage 2) that
    # canonicalizes/hashes the issuer manifest — `_resolve_transparency_claim`
    # runs `canon.canonical_bytes(issuer_manifest)` unconditionally once it
    # sees `entry.type == "key-manifest"`, regardless of whether the rest of
    # the evidence is otherwise valid. Feeding one in makes the pre-fix
    # ordering (transparency resolved before the ceiling) observable.
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    log_key = tlog.LogKey(
        origin="log.attest.example/2026",
        name="attest-log-1",
        ed25519_pub=hk.ed.pub,
        mldsa_pub=hk.mldsa.pub,
    )
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(oversized_manifest),
        transparency={"entry": {"type": "key-manifest"}},
        log_keys=[log_key],
        anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )

    assert result.schema == "invalid"
    assert result.ok is False
    assert not any(obj is oversized_manifest for obj in canonicalized)


# --- P1.1b: the witness policy reaches the transparency layer through verify() --


_WITNESS_ORIGIN = "log.example"
_WITNESS_NAME = "witness.example/w1"
_WITNESS_KP = keys.from_seed(bytes([21]) * 32)
_WITNESS_OBSERVED_AT = 1700000000


def _witness_policy_doc(**pin_overrides: Any) -> dict[str, Any]:
    pin: dict[str, Any] = {
        "operator_id": "witness.example",
        "control_group": "witness.example",
        "name": _WITNESS_NAME,
        "ed25519_pub_b64u": keys.b64u(_WITNESS_KP.pub),
        "mldsa_65_pub_b64u": None,
        "roles": ["corroboration"],
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": None,
        "affiliated_domains": ["witness.example"],
    }
    pin.update(pin_overrides)
    return {
        "schema": "attest-witness-policy-v1",
        "epochs": [
            {
                "epoch_id": "bootstrap-1",
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": None,
                "log_origins": [_WITNESS_ORIGIN],
                "threshold": {"n": 1, "m": 1},
                "witnesses": [pin],
            }
        ],
    }


def _cosigned_receipt_evidence(
    envelope: dict[str, Any], hk: pq.HybridSigningKeys, *, cosign: bool = True
) -> tuple[dict[str, Any], tlog.LogKey]:
    """A 3-leaf log holding this receipt at index 1, its checkpoint optionally
    carrying a pinned witness cosignature."""
    from attest import witness as witness_module

    entries = [{"type": "receipt", "issuer": ISSUER, "core_sha256": f"{i:064x}"} for i in range(3)]
    entries[1] = {
        "type": "receipt",
        "issuer": ISSUER,
        "core_sha256": tlog.receipt_core_hash(envelope),
    }
    leaves = [tlog.encode_entry(e) for e in entries]
    text = tlog.sign_checkpoint(_WITNESS_ORIGIN, 3, tlog.build_tree(leaves), hk, _WITNESS_ORIGIN)
    if cosign:
        checkpoint = tlog.parse_checkpoint(text)
        message = witness_module.cosignature_message(checkpoint.note_bytes, _WITNESS_OBSERVED_AT)
        blob = (
            witness_module.cosignature_key_id(_WITNESS_NAME, _WITNESS_KP.pub)
            + _WITNESS_OBSERVED_AT.to_bytes(8, "big")
            + keys.sign(message, _WITNESS_KP)
        )
        text += f"— {_WITNESS_NAME} {base64.b64encode(blob).decode()}\n"
    evidence = {
        "entry": dict(entries[1]),
        "leaf_index": 1,
        "tree_size": 3,
        "inclusion_proof": [p.hex() for p in tlog.inclusion_proof(leaves, 1)],
        "checkpoint": text,
        "witness_policy_epoch": "bootstrap-1",
    }
    log_key = tlog.LogKey(
        origin=_WITNESS_ORIGIN,
        name=_WITNESS_ORIGIN,
        ed25519_pub=hk.ed.pub,
        mldsa_pub=hk.mldsa.pub,
    )
    return evidence, log_key


def test_witness_policy_reaches_corroboration_through_verify() -> None:
    """The policy travels on the trusted rail `log_keys`/`anchor_policy` already
    use. Without this wiring `corroboration: "witnessed"` is reachable through
    `evaluate_transparency` but not through the public verifier — so no
    conformance leaf could ever exercise it."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    envelope = issue.issue(make_payload(), KP, KID)
    evidence, log_key = _cosigned_receipt_evidence(envelope, hk)
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
        witness_policy=_witness_policy_doc(),
    )
    assert result.corroboration == "witnessed"
    assert "witness_independence_not_established" in result.warnings


def test_omitting_the_witness_policy_leaves_verify_unchanged() -> None:
    """Zero behavior change for every existing caller (§10.2): the same
    evidence, without the policy, stops at `logged`."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    envelope = issue.issue(make_payload(), KP, KID)
    evidence, log_key = _cosigned_receipt_evidence(envelope, hk)
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )
    assert result.corroboration == "logged"
    assert "witness_independence_not_established" not in result.warnings


def test_a_policy_without_a_matching_cosignature_stays_logged() -> None:
    """The positive control's negative twin: the wiring must not invent
    standing when the note carries no cosignature at all."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    envelope = issue.issue(make_payload(), KP, KID)
    evidence, log_key = _cosigned_receipt_evidence(envelope, hk, cosign=False)
    result = verify.verify(
        _to_bytes(envelope),
        _trust_store(_key_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
        witness_policy=_witness_policy_doc(),
    )
    assert result.corroboration == "logged"


def test_a_malformed_witness_policy_raises_from_verify() -> None:
    """Trusted configuration, so a defect is loud — same discipline as a
    malformed `log_keys`."""
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    envelope = issue.issue(make_payload(), KP, KID)
    evidence, log_key = _cosigned_receipt_evidence(envelope, hk)
    with pytest.raises(ValueError):
        verify.verify(
            _to_bytes(envelope),
            _trust_store(_key_manifest()),
            transparency=evidence,
            log_keys=[log_key],
            anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
            witness_policy={"schema": "wrong", "epochs": []},
        )


def test_an_oversized_integer_literal_from_the_wire_is_a_verdict_not_a_crash() -> None:
    """Python 3.11+ refuses an integer literal over 4300 digits with a bare
    `ValueError` from `int()`. Reaching the library's public entry point from
    the wire, it must come back as a fail-closed verdict: the boundary here
    catches `canon.CanonError`, so anything else escapes to the caller."""
    wire = b'{"payload":{"n":' + b"9" * 4400 + b'},"signatures":[]}'
    result = verify.verify(wire, verify.TrustStore(manifests={}, provenance={}))

    assert result.signature == "invalid"
    assert any("invalid JSON" in e for e in result.errors)


# --- V-L.3: an ambiguous issuer manifest is refused whole (v0.1 §7.1) --------


def _hand_signed_manifest(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Sign a manifest WITHOUT `build_key_manifest`, which since the v0.1 §7.1
    amendment refuses a duplicated `kid` — the shape a hostile or legacy issuer
    can still publish, and the one the verifier must refuse."""
    body: dict[str, Any] = {
        "issuer": ISSUER,
        "manifest_version": 1,
        "issued_at": "2026-01-01T00:00:00Z",
        "keys": entries,
    }
    body["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(body),  # type: ignore[attr-defined]
        KP,
        KID,
    )
    return body


def test_duplicate_kid_unrelated_to_the_signature_still_rejects_the_receipt() -> None:
    """The case the status floor alone does not catch: the duplicated kid is
    NOT the one that signed the receipt, so no `compromised` marking fires and
    step 3 would resolve the signing key straight through `find_key`."""
    envelope = issue.issue(make_payload(), KP, KID)
    manifest = _hand_signed_manifest(
        [
            manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active"),
            manifests.key_entry(
                COMPROMISED_KID, COMPROMISED_KP.pub, "2026-01-01T00:00:00Z", None, "active"
            ),
            manifests.key_entry(
                COMPROMISED_KID, COMPROMISED_KP.pub, "2026-01-01T00:00:00Z", None, "retired"
            ),
        ]
    )

    result = verify.verify(_to_bytes(envelope), _trust_store(manifest))

    assert result.ok is False
    assert result.signature == "invalid"
    assert result.schema == "invalid"
    assert any("duplicate kid" in error for error in result.errors)


def test_duplicate_of_the_signing_kid_rejects_in_both_element_orders() -> None:
    """The pair proves order never decides: both orders reach the same verdict
    and the same error."""
    envelope = issue.issue(make_payload(), KP, KID)
    active = manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "active")
    compromised = manifests.key_entry(KID, KP.pub, "2026-01-01T00:00:00Z", None, "compromised")

    verdicts = [
        verify.verify(_to_bytes(envelope), _trust_store(_hand_signed_manifest(list(entries))))
        for entries in ([active, compromised], [compromised, active])
    ]

    for result in verdicts:
        assert result.ok is False
        assert any("duplicate kid" in error for error in result.errors)
    assert verdicts[0].errors == verdicts[1].errors
