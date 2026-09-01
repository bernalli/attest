"""Anchored compromise-cutoff verification tests."""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any

import pytest

from attest import anchor, canon, issue, keys, manifests, pq, tlog, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
OTHER_ISSUER = "other.example.com"
ORIGIN = "log.attest.example/2026"
LOG_NAME = "attest-log-1"

KPA = keys.from_seed(bytes([90]) * 32)
KPB = keys.from_seed(bytes([91]) * 32)
KPC = keys.from_seed(bytes([92]) * 32)
KPD = keys.from_seed(bytes([93]) * 32)

KID_A = f"{ISSUER}/keys/test#ed25519-a"
KID_B = f"{ISSUER}/keys/test#ed25519-b"
OTHER_KID = f"{OTHER_ISSUER}/keys/test#ed25519-a"


def _entry(
    kid: str,
    kp: keys.SigningKeyPair,
    status: str = "active",
    valid_to: str | None = None,
) -> dict[str, Any]:
    return manifests.key_entry(
        kid,
        kp.pub,
        "2026-01-01T00:00:00Z",
        valid_to,
        status,
    )


def _manifest(
    version: int,
    entries: list[dict[str, Any]],
    signing_kp: keys.SigningKeyPair,
    signing_kid: str,
    issuer: str = ISSUER,
) -> dict[str, Any]:
    return manifests.build_key_manifest(
        issuer,
        version,
        "2026-06-01T00:00:00Z",
        entries,
        signing_kp,
        signing_kid,
    )


def _active_manifest() -> dict[str, Any]:
    return _manifest(1, [_entry(KID_A, KPA), _entry(KID_B, KPB)], KPB, KID_B)


def _compromise_manifest(
    version: int = 2,
    signing_kp: keys.SigningKeyPair = KPB,
    signing_kid: str = KID_B,
    *,
    issuer: str = ISSUER,
) -> dict[str, Any]:
    kid = KID_A if issuer == ISSUER else OTHER_KID
    return _manifest(
        version,
        [_entry(kid, KPA, "compromised"), _entry(KID_B, KPB)],
        signing_kp,
        signing_kid,
        issuer=issuer,
    )


def _receipt(kp: keys.SigningKeyPair = KPA, kid: str = KID_A) -> dict[str, Any]:
    payload = make_payload(issuer={"id": ISSUER, "display_name": "Example Games Store"})
    return issue.issue(payload, kp, kid)


def _verify_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _trust_store(
    manifest: dict[str, Any],
    *,
    chains: dict[str, list[dict[str, Any]]] | None = None,
) -> verify.TrustStore:
    return verify.TrustStore(
        manifests={ISSUER: manifest},
        provenance={ISSUER: "tls"},
        chains=chains or {},
    )


def _hybrid_log_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _log_key(hk: pq.HybridSigningKeys) -> tlog.LogKey:
    return tlog.LogKey(
        origin=ORIGIN,
        name=LOG_NAME,
        ed25519_pub=hk.ed.pub,
        mldsa_pub=hk.mldsa.pub,
    )


def _anchored_evidence(
    entry: dict[str, Any],
    hk: pq.HybridSigningKeys,
    header_time: int,
    *,
    anchored: bool = True,
) -> tuple[dict[str, Any], anchor.PinnedHeader | None]:
    leaf = tlog.encode_entry(entry)
    root = tlog.build_tree([leaf])
    checkpoint_text = tlog.sign_checkpoint(ORIGIN, 1, root, hk, LOG_NAME)
    evidence: dict[str, Any] = {
        "entry": dict(entry),
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": [],
        "checkpoint": checkpoint_text,
    }
    if not anchored:
        return evidence, None

    signed_note_bytes = tlog.parse_checkpoint(checkpoint_text).signed_note_bytes
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(signed_note_bytes).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    header_hash = hashlib.sha256(
        f"header-{header_time}".encode("ascii") + signed_note_bytes
    ).hexdigest()
    proof = {
        "kind": "ots",
        "ops": [["append", sibling.hex()], ["sha256"], ["prepend", prefix.hex()], ["sha256"]],
        "header_merkle_root": acc.hex(),
        "header_time": header_time,
        "header_hash": header_hash,
    }
    evidence["anchors"] = {
        "checkpoint": checkpoint_text,
        "proofs": [proof],
        "anchor_profile": "signed-note-v2",
    }
    return evidence, anchor.PinnedHeader(
        header_hash=header_hash,
        merkle_root=acc.hex(),
        time=header_time,
    )


def _policy(*headers: anchor.PinnedHeader | None) -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(
        pinned_headers={header.header_hash: header for header in headers if header is not None},
        crqc_horizon=None,
    )


def _receipt_entry(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "receipt",
        "issuer": ISSUER,
        "core_sha256": tlog.receipt_core_hash(envelope),
    }


def _manifest_entry(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "key-manifest",
        "issuer": manifest.get("issuer"),
        "manifest_version": manifest.get("manifest_version"),
        "manifest_sha256": hashlib.sha256(canon.canonical_bytes(manifest)).hexdigest(),
    }


def _claim(
    manifest: dict[str, Any],
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {"manifest": manifest, "evidence": evidence or {}}


def _verify_with_receipt_anchor(
    envelope: dict[str, Any],
    trust_store: verify.TrustStore,
    compromise_view: list[dict[str, Any]],
    *,
    receipt_time: int = 1_700_000_000,
    claim_manifest: dict[str, Any] | None = None,
    claim_time: int | None = None,
    claim_anchored: bool = True,
) -> verify.VerificationResult:
    hk = _hybrid_log_keys()
    receipt_evidence, receipt_header = _anchored_evidence(
        _receipt_entry(envelope), hk, receipt_time
    )
    headers = [receipt_header]
    if claim_manifest is not None and claim_time is not None:
        claim_evidence, claim_header = _anchored_evidence(
            _manifest_entry(claim_manifest),
            hk,
            claim_time,
            anchored=claim_anchored,
        )
        compromise_view = [_claim(claim_manifest, claim_evidence)]
        headers.append(claim_header)
    return verify.verify(
        _verify_bytes(envelope),
        trust_store,
        transparency=receipt_evidence,
        log_keys=[_log_key(hk)],
        anchor_policy=_policy(*headers),
        compromise_view=compromise_view,
    )


def test_compromise_view_must_be_a_list() -> None:
    with pytest.raises(TypeError, match="compromise_view must be a list of claims or None"):
        verify.verify(
            _verify_bytes(_receipt()),
            _trust_store(_active_manifest()),
            compromise_view={"claims": []},  # type: ignore[arg-type]
        )


def test_claim_with_issuer_mismatch_is_ignored_with_warning() -> None:
    envelope = _receipt()
    other_claim = _compromise_manifest(issuer=OTHER_ISSUER, signing_kp=KPD, signing_kid=OTHER_KID)

    result = _verify_with_receipt_anchor(
        envelope,
        _trust_store(_active_manifest()),
        [_claim(other_claim)],
    )

    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == ("compromise_cutoff_claim_ignored",)


def test_claim_with_key_material_mismatch_is_ignored_with_warning() -> None:
    envelope = _receipt()
    claim_manifest = _manifest(
        2,
        [_entry(KID_A, KPC, "compromised"), _entry(KID_B, KPB)],
        KPB,
        KID_B,
    )

    result = _verify_with_receipt_anchor(
        envelope,
        _trust_store(_active_manifest()),
        [_claim(claim_manifest)],
    )

    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == ("compromise_cutoff_claim_ignored",)


def test_compromised_declaring_signer_establishes_floor_but_no_cutoff() -> None:
    envelope = _receipt()
    trusted = _manifest(
        3,
        [_entry(KID_A, KPA), _entry(KID_B, KPB, "compromised")],
        KPB,
        KID_B,
    )
    claim_manifest = _compromise_manifest(signing_kp=KPB, signing_kid=KID_B)

    result = _verify_with_receipt_anchor(
        envelope,
        _trust_store(trusted),
        [_claim(claim_manifest, {"entry": {"type": "receipt"}})],
    )

    assert result.signature == "valid"
    assert result.ok is True
    # The trusted manifest here no longer carries the marking that the older
    # claimed manifest does, so v0.1 §7.3 rev 8 also reports the provenance.
    assert result.warnings == (
        "compromise_marking_retracted",
        "compromise_cutoff_unanchored",
    )


def test_cutoff_evaluator_warnings_propagate_when_entry_mismatches() -> None:
    envelope = _receipt()
    trusted = _active_manifest()
    claim_manifest = _compromise_manifest()
    hk = _hybrid_log_keys()
    receipt_evidence, receipt_header = _anchored_evidence(
        _receipt_entry(envelope), hk, 1_700_000_000
    )
    wrong_entry = dict(_manifest_entry(claim_manifest))
    wrong_entry["manifest_sha256"] = hashlib.sha256(b"different-manifest").hexdigest()
    claim_evidence, _claim_header = _anchored_evidence(wrong_entry, hk, 1_700_003_600)

    result = verify.verify(
        _verify_bytes(envelope),
        _trust_store(trusted),
        transparency=receipt_evidence,
        log_keys=[_log_key(hk)],
        anchor_policy=_policy(receipt_header),
        compromise_view=[_claim(claim_manifest, claim_evidence)],
    )

    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == (
        "transparency_entry_mismatch",
        "compromise_cutoff_unanchored",
    )


def test_compromise_view_cap_accepts_sixty_four_claims_but_skips_sixty_five() -> None:
    envelope = _receipt()
    invalid_claim = _claim(
        _compromise_manifest(issuer=OTHER_ISSUER, signing_kp=KPD, signing_kid=OTHER_KID)
    )

    accepted = _verify_with_receipt_anchor(
        envelope,
        _trust_store(_active_manifest()),
        [invalid_claim] * 64,
    )
    skipped = _verify_with_receipt_anchor(
        envelope,
        _trust_store(_active_manifest()),
        [invalid_claim] * 65,
    )

    assert accepted.signature == "valid"
    assert accepted.warnings == ("compromise_cutoff_claim_ignored",)
    # An over-ceiling view is refused, not silently dropped: v0.2 §19.2's
    # fail-closed effect. Until 2026-09-01 the two lines below asserted
    # `"valid"` and `()`, which pinned the fail-open behaviour — a view padded
    # past the ceiling made a genuine declaration stop biting, with no warning.
    # This fixture pads with already-invalid claims, so nothing is lost here;
    # `test_oversized_view_carrying_a_genuine_declaration_does_not_certify_the_key`
    # is the one that shows what the silence was costing.
    assert skipped.signature == "invalid"
    assert any("compromise view exceeds 64 claims" in error for error in skipped.errors)


def test_oversized_compromise_view_does_not_suppress_held_chain_floor() -> None:
    envelope = _receipt()
    v1 = _active_manifest()
    v2 = _compromise_manifest()
    v3 = _manifest(3, [_entry(KID_A, KPA), _entry(KID_B, KPB)], KPB, KID_B)
    invalid_claim = _claim(
        _compromise_manifest(issuer=OTHER_ISSUER, signing_kp=KPD, signing_kid=OTHER_KID)
    )

    result = verify.verify(
        _verify_bytes(envelope),
        _trust_store(v3, chains={ISSUER: [v1, v2, v3]}),
        compromise_view=[invalid_claim] * 65,
    )

    assert result.signature == "invalid"
    assert result.ok is False
    assert any("compromised" in error for error in result.errors)


def test_logged_cutoff_evidence_leaves_anchored_receipt_rescued_as_unanchored() -> None:
    envelope = _receipt()
    trusted = _active_manifest()
    claim_manifest = _compromise_manifest()

    result = _verify_with_receipt_anchor(
        envelope,
        _trust_store(trusted),
        [],
        claim_manifest=claim_manifest,
        claim_time=1_700_003_600,
        claim_anchored=False,
    )

    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == ("compromise_cutoff_unanchored",)


def test_anchored_receipt_before_cutoff_is_rescued() -> None:
    envelope = _receipt()
    trusted = _active_manifest()
    claim_manifest = _compromise_manifest()

    result = _verify_with_receipt_anchor(
        envelope,
        _trust_store(trusted),
        [],
        receipt_time=1_700_000_000,
        claim_manifest=claim_manifest,
        claim_time=1_700_003_600,
    )

    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == ("compromise_rescue_applied",)


def test_anchored_receipt_at_or_after_cutoff_is_rejected() -> None:
    envelope = _receipt()
    trusted = _active_manifest()
    claim_manifest = _compromise_manifest()

    result = _verify_with_receipt_anchor(
        envelope,
        _trust_store(trusted),
        [],
        receipt_time=1_700_003_600,
        claim_manifest=claim_manifest,
        claim_time=1_700_003_600,
    )

    assert result.signature == "invalid"
    assert result.ok is False
    assert result.warnings == ("compromise_rescue_receipt_after_cutoff",)
    assert any("compromised" in error for error in result.errors)


def test_logged_receipt_claim_does_not_rescue_compromised_key() -> None:
    envelope = _receipt()
    hk = _hybrid_log_keys()
    receipt_evidence, _receipt_header = _anchored_evidence(
        _receipt_entry(envelope),
        hk,
        1_700_000_000,
        anchored=False,
    )
    claim_manifest = _compromise_manifest()
    claim_evidence, claim_header = _anchored_evidence(
        _manifest_entry(claim_manifest),
        hk,
        1_700_003_600,
    )

    result = verify.verify(
        _verify_bytes(envelope),
        _trust_store(_active_manifest()),
        transparency=receipt_evidence,
        log_keys=[_log_key(hk)],
        anchor_policy=_policy(claim_header),
        compromise_view=[_claim(claim_manifest, claim_evidence)],
    )

    assert result.signature == "invalid"
    assert result.ok is False
    assert result.warnings == ("compromise_rescue_requires_anchored_receipt",)


def test_unparseable_receipt_anchor_time_does_not_rescue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_evaluate(*_args: object, **_kwargs: object) -> tuple[str, str, str, str]:
        return "anchored_before:not-a-date", "logged", "not_checked", "receipt"

    monkeypatch.setattr(verify, "_evaluate_transparency_claim", fake_evaluate)

    result = verify.verify(
        _verify_bytes(_receipt()),
        _trust_store(
            _manifest(
                2,
                [_entry(KID_A, KPA, "compromised"), _entry(KID_B, KPB)],
                KPB,
                KID_B,
            )
        ),
        transparency={},
        log_keys=[_log_key(_hybrid_log_keys())],
        anchor_policy=anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
        compromise_view=[],
    )

    assert result.signature == "invalid"
    assert result.ok is False
    assert result.warnings == ("compromise_rescue_requires_anchored_receipt",)


def test_chain_floor_rejects_regressed_latest_manifest_but_latest_only_cannot_see_it() -> None:
    envelope = _receipt()
    v1 = _active_manifest()
    v2 = _compromise_manifest()
    v3 = _manifest(3, [_entry(KID_A, KPA), _entry(KID_B, KPB)], KPB, KID_B)

    with_chain = verify.verify(
        _verify_bytes(envelope),
        _trust_store(v3, chains={ISSUER: [v1, v2, v3]}),
        compromise_view=[],
    )
    latest_only = verify.verify(
        _verify_bytes(envelope),
        _trust_store(v3),
        compromise_view=[],
    )

    assert with_chain.signature == "invalid"
    assert with_chain.ok is False
    assert any("compromised" in error for error in with_chain.errors)
    assert latest_only.signature == "valid"
    assert latest_only.ok is True


def test_iso_helper_stays_utc_z_for_anchor_assertions() -> None:
    rendered = datetime.datetime.fromtimestamp(1_700_000_000, tz=datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert rendered == "2023-11-14T22:13:20Z"


def test_inadmissible_compromise_claim_does_not_discard_authenticated_cutoff() -> None:
    """One junk claim must not suppress an authenticated cutoff.

    The compromise view carries the only evidence v0.1 §6.2 lets invalidate a
    receipt, so discarding the whole view over one inadmissible claim moves the
    verdict toward VALID — the opposite of the failure direction every other
    admission path takes.
    """
    envelope = _receipt()
    trusted = _active_manifest()
    claim_manifest = _compromise_manifest()
    hk = _hybrid_log_keys()
    receipt_evidence, receipt_header = _anchored_evidence(
        _receipt_entry(envelope), hk, 1_700_003_600
    )
    claim_evidence, claim_header = _anchored_evidence(
        _manifest_entry(claim_manifest), hk, 1_700_003_600
    )

    result = verify.verify(
        _verify_bytes(envelope),
        _trust_store(trusted),
        transparency=receipt_evidence,
        log_keys=[_log_key(hk)],
        anchor_policy=_policy(receipt_header, claim_header),
        compromise_view=[_claim(claim_manifest, claim_evidence), {"padding": 1.5}],
    )

    assert result.signature == "invalid"
    assert result.ok is False


def test_oversized_view_carrying_a_genuine_declaration_does_not_certify_the_key() -> None:
    """A view padded past the ceiling must not quietly restore a compromised key.

    The claims a size guard drops are the ones that can only NARROW the set of
    valid signatures, so dropping them in silence hands anyone able to append to
    this channel — the one v0.2 §19.2 blesses for untrusted transport — a way to
    switch the v0.1 §7.3 floor back off. `_revocation_state` already refuses the
    same padding attack on the sibling rail, and §6.3 requires the section owning
    a rail to define the fail-closed effect of a unit it does not admit.

    The existing ceiling tests cannot see this: they pad with claims that are
    already invalid, so no genuine declaration is ever the thing that falls off
    the end.
    """
    envelope = _receipt()
    trusted = _active_manifest()
    claim_manifest = _compromise_manifest()
    hk = _hybrid_log_keys()
    receipt_evidence, receipt_header = _anchored_evidence(
        _receipt_entry(envelope), hk, 1_700_003_600
    )
    claim_evidence, claim_header = _anchored_evidence(
        _manifest_entry(claim_manifest), hk, 1_700_003_600
    )
    padding = _claim(
        _compromise_manifest(issuer=OTHER_ISSUER, signing_kp=KPD, signing_kid=OTHER_KID)
    )

    result = verify.verify(
        _verify_bytes(envelope),
        _trust_store(trusted),
        transparency=receipt_evidence,
        log_keys=[_log_key(hk)],
        anchor_policy=_policy(receipt_header, claim_header),
        compromise_view=[_claim(claim_manifest, claim_evidence)] + [padding] * 64,
    )

    assert result.signature == "invalid"
    assert result.ok is False
