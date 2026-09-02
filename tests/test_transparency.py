"""Transparency/corroboration evaluator: decision-order rules + adversarial
evidence handling.

Fixtures build a real 3-leaf transparency log by hand (via `tlog`'s own
builder side — `build_tree`/`inclusion_proof`/`consistency_proof` — which is
the intended, documented way to produce proofs the verify side consumes; see
`tlog.py`'s own module docstring). Every negative test is a controlled
mutation of the one working fixture, so a single assertion isolates exactly
one failure mode, mirroring `test_anchor.py`'s style.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, cast

import pytest

from attest import anchor, canon, issue, keys, manifests, pq, tlog, transparency, verify
from tests.helpers import make_payload

ORIGIN = "log.attest.example/2026"
LOG_NAME = "attest-log-1"


def _hybrid_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _log_key(hk: pq.HybridSigningKeys, origin: str = ORIGIN, name: str = LOG_NAME) -> tlog.LogKey:
    return tlog.LogKey(origin=origin, name=name, ed25519_pub=hk.ed.pub, mldsa_pub=hk.mldsa.pub)


def _entries(n: int, salt: str = "leaf") -> list[dict[str, Any]]:
    return [
        {
            "type": "receipt",
            "issuer": "issuer.example",
            "core_sha256": hashlib.sha256(f"{salt}-{i}".encode()).hexdigest(),
        }
        for i in range(n)
    ]


def _no_horizon_policy() -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


class _GetRaisesDict(dict[str, Any]):
    """Hostile evidence mapping whose ordinary accessors are not safe."""

    def get(self, key: object, default: object = None) -> object:
        raise KeyError(key)

    def __getitem__(self, key: str) -> Any:
        raise KeyError(key)


class _EqualityRaisesString(str):
    """Schema-valid evidence value whose comparison is hostile."""

    def __eq__(self, other: object) -> bool:
        raise RuntimeError("hostile equality")


class _TreeSizeChangesDict(dict[str, Any]):
    """Return different tree sizes on successive access attempts."""

    def __init__(self, evidence: dict[str, Any]) -> None:
        super().__init__(evidence)
        self.tree_size_reads = 0

    def _tree_size(self) -> int:
        self.tree_size_reads += 1
        return 777 if self.tree_size_reads == 1 else 1

    def get(self, key: str, default: Any = None) -> Any:
        if key == "tree_size":
            return self._tree_size()
        return super().get(key, default)

    def __getitem__(self, key: str) -> Any:
        if key == "tree_size":
            return self._tree_size()
        return super().__getitem__(key)


class _RaisesOnThirdEqualityString(str):
    """Behaves normally for claim resolution, then raises during post-processing."""

    comparisons: int

    def __new__(cls, value: str) -> _RaisesOnThirdEqualityString:
        instance = super().__new__(cls, value)
        instance.comparisons = 0
        return instance

    def __eq__(self, other: object) -> bool:
        self.comparisons += 1
        if self.comparisons == 3:
            raise RuntimeError("hostile equality")
        return super().__eq__(other)


class _Bundle:
    """A working 3-leaf log fixture: entry-under-test at index 1, signed
    checkpoint at tree_size=3, and its inclusion proof — everything
    `evaluate_transparency` needs for a passing evaluation out of the box.
    Individual tests mutate copies of `evidence`/`log_keys`/etc. to isolate
    one failure mode at a time.
    """

    def __init__(self) -> None:
        self.hk = _hybrid_keys()
        self.log_key = _log_key(self.hk)
        self.entries = _entries(3)
        self.leaves = [tlog.encode_entry(e) for e in self.entries]
        self.root = tlog.build_tree(self.leaves)
        self.proof = tlog.inclusion_proof(self.leaves, 1)
        self.checkpoint_text = tlog.sign_checkpoint(ORIGIN, 3, self.root, self.hk, LOG_NAME)
        self.entry = self.entries[1]

    def evidence(self) -> dict[str, Any]:
        return {
            "entry": dict(self.entry),
            "leaf_index": 1,
            "tree_size": 3,
            "inclusion_proof": [p.hex() for p in self.proof],
            "checkpoint": self.checkpoint_text,
        }

    def log_keys(self) -> list[tlog.LogKey]:
        return [self.log_key]

    def expected_entry(self) -> dict[str, Any]:
        return dict(self.entry)


def _evaluate(
    bundle: _Bundle, evidence: dict[str, Any], **overrides: Any
) -> transparency.TransparencyResult:
    kwargs: dict[str, Any] = {
        "log_keys": bundle.log_keys(),
        "expected_origin": ORIGIN,
        "policy": _no_horizon_policy(),
        "expected_entry": bundle.expected_entry(),
    }
    kwargs.update(overrides)
    return transparency.evaluate_transparency(evidence, **kwargs)


# --------------------------------------------------------------------------
# Happy path + decision order steps 1-3.
# --------------------------------------------------------------------------


def test_evaluate_transparency_returns_logged_for_a_fully_valid_bundle() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, bundle.evidence())
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.warnings == []


def test_evaluate_transparency_flags_entry_schema_violation() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    del evidence["entry"]["core_sha256"]  # violates the closed receipt schema
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["entry_invalid"]


def test_evaluate_transparency_flags_entry_mismatch_against_expected_entry() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["entry"]["core_sha256"] = hashlib.sha256(b"different-artifact").hexdigest()
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["transparency_entry_mismatch"]


def test_evaluate_transparency_reports_entry_mismatch_before_checkpoint_failure() -> None:
    # Both the entry AND the checkpoint are broken; decision order requires
    # step 1 (entry) to short-circuit before step 2 (checkpoint) is ever
    # attempted — asserts the ORDERING, not just that one of them fails.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["entry"]["core_sha256"] = hashlib.sha256(b"different-artifact").hexdigest()
    evidence["checkpoint"] = "not even a parseable checkpoint\n"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["transparency_entry_mismatch"]


def test_evaluate_transparency_flags_non_dict_entry_field() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["entry"] = "not-a-dict"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["entry_invalid"]


def test_evaluate_transparency_flags_checkpoint_field_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["checkpoint"] = 12345
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["checkpoint_invalid"]


def test_evaluate_transparency_flags_checkpoint_verification_failure_for_unknown_origin() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, bundle.evidence(), expected_origin="different-log/2026")
    assert result.warnings == ["checkpoint_verification_failed"]


def test_evaluate_transparency_flags_checkpoint_signed_by_untrusted_key() -> None:
    bundle = _Bundle()
    other_hk = _hybrid_keys()
    other_key = _log_key(other_hk)  # same origin, different keypair -> signature won't verify
    result = _evaluate(bundle, bundle.evidence(), log_keys=[other_key])
    assert result.warnings == ["checkpoint_verification_failed"]


def test_evaluate_transparency_tries_next_log_key_when_first_does_not_verify() -> None:
    # Log-key rotation: multiple pinned keys share the origin, only the
    # second one actually matches the checkpoint's signature.
    bundle = _Bundle()
    stale_hk = _hybrid_keys()
    stale_key = _log_key(stale_hk)
    result = _evaluate(bundle, bundle.evidence(), log_keys=[stale_key, bundle.log_key])
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.warnings == []


def test_evaluate_transparency_flags_leaf_index_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["leaf_index"] = "1"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["leaf_index_invalid"]


def test_evaluate_transparency_rejects_bool_leaf_index() -> None:
    # bool-is-int trap: isinstance(True, int) is True in Python.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["leaf_index"] = True
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["leaf_index_invalid"]


def test_evaluate_transparency_flags_tree_size_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["tree_size"] = "3"
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["tree_size_invalid"]


def test_evaluate_transparency_rejects_bool_tree_size() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["tree_size"] = True
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["tree_size_invalid"]


def test_evaluate_transparency_flags_tree_size_mismatch_against_checkpoint() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["tree_size"] = 4  # checkpoint actually attests to tree_size=3
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["tree_size_mismatch"]


def test_evaluate_transparency_flags_non_list_inclusion_proof() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    # A tuple of otherwise-valid proof entries would reach the successful
    # path if the explicit list guard were deleted.
    evidence["inclusion_proof"] = tuple(evidence["inclusion_proof"])
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


def test_evaluate_transparency_rejects_uppercase_inclusion_proof_entry() -> None:
    # Uppercase one entry but keep the proof otherwise complete: bytes.fromhex
    # would decode it to the identical bytes as the lowercase original, so
    # this isolates the lowercase-only shape guard from a truncated/corrupted
    # proof (which would fail verification for an unrelated reason).
    bundle = _Bundle()
    evidence = bundle.evidence()
    proof = list(evidence["inclusion_proof"])
    proof[0] = proof[0].upper()
    evidence["inclusion_proof"] = proof
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


def test_evaluate_transparency_rejects_wrong_length_inclusion_proof_entry() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["inclusion_proof"] = ["aa" * 31]
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


def test_evaluate_transparency_caps_oversized_inclusion_proof_list() -> None:
    # A distinct warning from "inclusion_proof_invalid" so this guard is
    # independently observable: tlog.verify_inclusion's own internal bound
    # would otherwise reject an oversized-but-well-formed proof with the
    # exact same generic outcome, masking removal of this cap.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["inclusion_proof"] = ["aa" * 32] * (transparency._MAX_PROOF_LEN + 1)
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_too_long"]


def test_evaluate_transparency_flags_inclusion_proof_that_does_not_verify() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["leaf_index"] = 0  # well-formed proof, but for the wrong leaf
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["inclusion_proof_invalid"]


# --------------------------------------------------------------------------
# Step 4: prior checkpoint / consistency / equivocation.
# --------------------------------------------------------------------------


def test_evaluate_transparency_no_warning_when_prior_checkpoint_is_consistent() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    consistency = tlog.consistency_proof(bundle.leaves, 2)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = [p.hex() for p in consistency]
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.warnings == []


def test_evaluate_transparency_detects_equivocation_on_inconsistent_prior() -> None:
    bundle = _Bundle()
    # A real proof for an honest 2->3 extension of a DIFFERENT tree (built
    # forward from tlog's own builder side, never round-tripped through the
    # verify side under test), presented against the bundle's actual
    # (unrelated) current root: verify_consistency must reject it.
    other_entries = _entries(2, salt="fork-prefix")
    other_leaves = [tlog.encode_entry(e) for e in other_entries]
    prior_root = tlog.build_tree(other_leaves)
    extended_leaves = [*other_leaves, bundle.leaves[2]]
    real_extension_proof = tlog.consistency_proof(extended_leaves, 2)
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)

    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = [p.hex() for p in real_extension_proof]
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_EQUIVOCATION_DETECTED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["log_equivocation_detected"]


def test_evaluate_transparency_equivocation_survives_configured_horizon() -> None:
    bundle = _Bundle()
    other_entries = _entries(2, salt="fork-prefix")
    other_leaves = [tlog.encode_entry(entry) for entry in other_entries]
    prior_root = tlog.build_tree(other_leaves)
    extended_leaves = [*other_leaves, bundle.leaves[2]]
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)

    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = [
        proof.hex() for proof in tlog.consistency_proof(extended_leaves, 2)
    ]
    note_bytes = tlog.parse_checkpoint(bundle.checkpoint_text).note_bytes
    anchors_evidence, policy_base, header_time = _working_ots_evidence(note_bytes)
    evidence["anchors"] = anchors_evidence
    policy = anchor.AnchorPolicy(
        pinned_headers=policy_base.pinned_headers, crqc_horizon=header_time - 1
    )

    result = _evaluate(bundle, evidence, policy=policy)
    assert result.transparency == transparency.TRANSPARENCY_EQUIVOCATION_DETECTED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["log_equivocation_detected"]


def test_evaluate_transparency_does_not_treat_unverifiable_prior_as_equivocation() -> None:
    # A prior checkpoint with a bad signature is NOT proof of equivocation —
    # fail-safe, not a hard verdict.
    bundle = _Bundle()
    forged_hk = _hybrid_keys()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    forged_prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, forged_hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = forged_prior_text
    evidence["consistency_proof"] = [p.hex() for p in tlog.consistency_proof(bundle.leaves, 2)]
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["prior_checkpoint_invalid"]


def test_evaluate_transparency_warns_when_prior_verifies_but_consistency_proof_missing() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    # consistency_proof intentionally absent
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.warnings == ["consistency_proof_missing"]


def test_evaluate_transparency_flags_malformed_consistency_proof_shape() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = ["not-hex"]
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["consistency_proof_invalid"]


def test_evaluate_transparency_flags_non_list_consistency_proof() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    # As above, this tuple contains a valid proof and would verify if the
    # list-only boundary guard were removed.
    evidence["consistency_proof"] = tuple(
        proof.hex() for proof in tlog.consistency_proof(bundle.leaves, 2)
    )
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["consistency_proof_invalid"]


def test_evaluate_transparency_caps_oversized_consistency_proof_list() -> None:
    # Load-bearing, not just defense-in-depth: without this cap, an oversized
    # proof reaches tlog.verify_consistency, which returns False on it (unlike
    # verify_inclusion's own internal bound) — and this module would then
    # misclassify it as TRANSPARENCY_EQUIVOCATION_DETECTED, a hard verdict,
    # for what is really just a malformed/garbage proof.
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = ["aa" * 32] * (transparency._MAX_PROOF_LEN + 1)
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["consistency_proof_too_long"]
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED


def test_evaluate_transparency_flags_prior_checkpoint_wrong_type() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = 42
    result = _evaluate(bundle, evidence)
    assert result.warnings == ["prior_checkpoint_invalid"]


def test_evaluate_transparency_flags_explicit_none_prior_checkpoint() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = None
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["prior_checkpoint_invalid"]


def test_evaluate_transparency_flags_explicit_none_consistency_proof() -> None:
    bundle = _Bundle()
    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = None
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["consistency_proof_invalid"]


# --------------------------------------------------------------------------
# Steps 6-7: anchors + CRQC horizon.
# --------------------------------------------------------------------------


def _working_ots_evidence(note_bytes: bytes) -> tuple[dict[str, Any], anchor.AnchorPolicy, int]:
    """Build a verifying `ots` anchor-evidence dict + matching policy, per
    the op-chain sequence documented in `test_anchor.py`."""
    header_time = 1700000000
    header_hash = "3a" * 32
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(note_bytes).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    ops = [["append", sibling.hex()], ["sha256"], ["prepend", prefix.hex()], ["sha256"]]
    proof = {
        "kind": "ots",
        "ops": ops,
        "header_merkle_root": acc.hex(),
        "header_time": header_time,
        "header_hash": header_hash,
    }
    pinned = anchor.PinnedHeader(header_hash=header_hash, merkle_root=acc.hex(), time=header_time)
    policy = anchor.AnchorPolicy(pinned_headers={header_hash: pinned}, crqc_horizon=None)
    dummy_sig_line = "— test-key AA==\n"
    checkpoint_text = note_bytes.decode() + "\n" + dummy_sig_line
    return {"checkpoint": checkpoint_text, "proofs": [proof]}, policy, header_time


def test_evaluate_transparency_sets_anchored_before_on_verified_pq_anchor() -> None:
    bundle = _Bundle()
    note_bytes = tlog.parse_checkpoint(bundle.checkpoint_text).note_bytes
    anchors_evidence, policy, header_time = _working_ots_evidence(note_bytes)
    evidence = bundle.evidence()
    evidence["anchors"] = anchors_evidence
    result = _evaluate(bundle, evidence, policy=policy)
    expected_iso = datetime.datetime.fromtimestamp(header_time, tz=datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert result.transparency == f"anchored_before:{expected_iso}"
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    # No `anchor_profile` on the anchor evidence (G4) -> legacy note-bytes-only
    # commitment, still fully verifiable (eternal verifiability) but flagged.
    assert result.warnings == ["anchor_note_only"]


def _working_ots_evidence_v2(
    checkpoint_text: str,
) -> tuple[dict[str, Any], anchor.AnchorPolicy, int]:
    """Same op sequence as `_working_ots_evidence`, but the accumulator seed
    is `tlog.parse_checkpoint(checkpoint_text).signed_note_bytes` — the FULL
    checkpoint text, header AND real signature lines (G4's v2 commitment) —
    and the evidence declares `anchor_profile: "signed-note-v2"`."""
    signed_note_bytes = tlog.parse_checkpoint(checkpoint_text).signed_note_bytes
    header_time = 1700000000
    header_hash = "4b" * 32
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(signed_note_bytes).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    ops = [["append", sibling.hex()], ["sha256"], ["prepend", prefix.hex()], ["sha256"]]
    proof = {
        "kind": "ots",
        "ops": ops,
        "header_merkle_root": acc.hex(),
        "header_time": header_time,
        "header_hash": header_hash,
    }
    pinned = anchor.PinnedHeader(header_hash=header_hash, merkle_root=acc.hex(), time=header_time)
    policy = anchor.AnchorPolicy(pinned_headers={header_hash: pinned}, crqc_horizon=None)
    return (
        {"checkpoint": checkpoint_text, "proofs": [proof], "anchor_profile": "signed-note-v2"},
        policy,
        header_time,
    )


def test_evaluate_transparency_v2_anchor_sets_anchored_before_without_note_only_warning() -> None:
    bundle = _Bundle()
    # The v2 accumulator commits over the checkpoint's REAL signature lines
    # (its `signed_note_bytes`), not a hand-built substitute — using
    # `bundle.checkpoint_text` (the actual hybrid-signed note) end to end is
    # what makes this test a genuine exercise of the v2 commitment.
    anchors_evidence, policy, header_time = _working_ots_evidence_v2(bundle.checkpoint_text)
    evidence = bundle.evidence()
    evidence["anchors"] = anchors_evidence
    result = _evaluate(bundle, evidence, policy=policy)
    expected_iso = datetime.datetime.fromtimestamp(header_time, tz=datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    assert result.transparency == f"anchored_before:{expected_iso}"
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.warnings == []


def test_iso8601_kat_pins_the_helper_independent_of_the_brief_arithmetic() -> None:
    assert transparency._iso8601(1700000000) == "2023-11-14T22:13:20Z"


def test_iso8601_renders_the_max_supported_pinned_header_time() -> None:
    assert transparency._iso8601(anchor._MAX_RENDERABLE_UNIX_TIME) == "9999-12-31T23:59:59Z"


def test_evaluate_transparency_flags_explicit_none_anchors() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["anchors"] = None
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["anchors_invalid"]


def test_evaluate_transparency_caps_to_not_checked_when_post_horizon_unanchored() -> None:
    # Base standing alone (no PQ-surviving anchor) cannot survive a declared
    # CRQC horizon: checkpoint signatures alone don't count.
    bundle = _Bundle()
    policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=1)
    result = _evaluate(bundle, bundle.evidence(), policy=policy)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["post_horizon_unanchored"]


def test_evaluate_transparency_horizon_cap_applies_when_anchor_too_late() -> None:
    bundle = _Bundle()
    note_bytes = tlog.parse_checkpoint(bundle.checkpoint_text).note_bytes
    anchors_evidence, policy_base, header_time = _working_ots_evidence(note_bytes)
    policy = anchor.AnchorPolicy(
        pinned_headers=policy_base.pinned_headers, crqc_horizon=header_time - 1
    )
    evidence = bundle.evidence()
    evidence["anchors"] = anchors_evidence
    result = _evaluate(bundle, evidence, policy=policy)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    # Step 6 (anchor upgrade, note-only classification) still runs before
    # step 7's horizon cap discards the standing it computed — the warning
    # survives the cap even though the upgraded `transparency` value doesn't.
    assert result.warnings == ["anchor_note_only", "post_horizon_unanchored"]


def test_evaluate_transparency_no_horizon_cap_when_crqc_horizon_none() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, bundle.evidence(), policy=_no_horizon_policy())
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.warnings == []


def test_evaluate_transparency_horizon_cap_overrides_prior_logged_anchor_state() -> None:
    # An anchor that IS present but never PQ-surviving (rfc3161-only) still
    # gets capped by a declared horizon.
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["anchors"] = {
        "checkpoint": bundle.checkpoint_text,
        "proofs": [{"kind": "rfc3161", "token_b64": "b3BhcXVl"}],
    }
    policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=1700000000)
    result = _evaluate(bundle, evidence, policy=policy)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.warnings == [
        "rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight",
        "post_horizon_unanchored",
    ]


def test_evaluate_transparency_surfaces_anchor_warnings_on_failed_anchor_evidence() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["anchors"] = {"checkpoint": bundle.checkpoint_text, "proofs": "not-a-list"}
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_LOGGED  # anchors are non-fatal
    assert result.warnings == ["evidence.proofs must be a list, got str"]


# --------------------------------------------------------------------------
# NEVER raises on malformed evidence.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_evidence", [None, [], "not-a-dict", 42, True])
def test_evaluate_transparency_never_raises_on_non_dict_evidence(bad_evidence: object) -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, cast(dict[str, Any], bad_evidence))
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.warnings == ["evidence_invalid"]


def test_evaluate_transparency_never_raises_when_required_fields_missing() -> None:
    bundle = _Bundle()
    result = _evaluate(bundle, {})
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.warnings == ["entry_invalid"]


def test_evaluate_transparency_confines_hostile_evidence_get() -> None:
    bundle = _Bundle()
    evidence = _GetRaisesDict(bundle.evidence())
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["evidence_evaluation_failed"]


def test_evaluate_transparency_confines_hostile_evidence_equality() -> None:
    bundle = _Bundle()
    evidence = bundle.evidence()
    evidence["entry"]["core_sha256"] = _EqualityRaisesString(evidence["entry"]["core_sha256"])
    result = _evaluate(bundle, evidence)
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ["evidence_evaluation_failed"]


# --------------------------------------------------------------------------
# Trusted-arg validation: raises TransparencyError, never degrades.
# --------------------------------------------------------------------------


def test_evaluate_transparency_raises_on_non_list_log_keys() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), log_keys=cast(list[tlog.LogKey], "not-a-list"))


def test_evaluate_transparency_raises_on_log_keys_list_with_non_logkey_element() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(
            bundle, bundle.evidence(), log_keys=cast(list[tlog.LogKey], [bundle.log_key, "x"])
        )


def test_evaluate_transparency_raises_on_malformed_log_key_field() -> None:
    bundle = _Bundle()
    malformed_key = tlog.LogKey(
        origin=ORIGIN,
        name=LOG_NAME,
        ed25519_pub=b"too-short",
        mldsa_pub=bundle.log_key.mldsa_pub,
    )
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), log_keys=[malformed_key])


def test_evaluate_transparency_raises_on_non_str_expected_origin() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), expected_origin=cast(str, 123))


def test_evaluate_transparency_raises_on_empty_expected_origin() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), expected_origin="")


def test_evaluate_transparency_raises_on_non_anchor_policy() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), policy=cast(anchor.AnchorPolicy, "not-a-policy"))


def test_evaluate_transparency_raises_on_malformed_policy_pinned_headers() -> None:
    bundle = _Bundle()
    malformed_policy = anchor.AnchorPolicy(
        pinned_headers=cast(dict[str, anchor.PinnedHeader], []), crqc_horizon=None
    )
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), policy=malformed_policy)


def test_evaluate_transparency_raises_on_non_dict_expected_entry() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), expected_entry=cast(dict[str, Any], "not-a-dict"))


def test_evaluate_transparency_raises_on_schema_invalid_expected_entry() -> None:
    bundle = _Bundle()
    with pytest.raises(transparency.TransparencyError):
        _evaluate(bundle, bundle.evidence(), expected_entry={"type": "receipt"})


# --------------------------------------------------------------------------
# Module contract: CORROBORATION_WITNESSED is unreachable with NO witness policy.
# --------------------------------------------------------------------------


def test_corroboration_witnessed_constant_is_defined() -> None:
    assert transparency.CORROBORATION_WITNESSED == "witnessed"


def test_corroboration_witnessed_never_returned_without_a_witness_policy() -> None:
    # Called with no `witness_policy`, every branch of evaluate_transparency
    # sets corroboration to CORROBORATION_NONE or CORROBORATION_LOGGED only —
    # rev 7 reaches "witnessed" through Step 8, which a caller opts into by
    # supplying a policy. Independently re-derive one evidence bundle per major
    # branch (base standing, consistent prior, equivocation, anchored,
    # horizon-capped) and assert none produces "witnessed".
    bundle = _Bundle()

    base = _evaluate(bundle, bundle.evidence())

    prior_root = tlog.build_tree(bundle.leaves[:2])
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)
    consistent_evidence = bundle.evidence()
    consistent_evidence["prior_checkpoint"] = prior_text
    consistent_evidence["consistency_proof"] = [
        p.hex() for p in tlog.consistency_proof(bundle.leaves, 2)
    ]
    consistent = _evaluate(bundle, consistent_evidence)

    note_bytes = tlog.parse_checkpoint(bundle.checkpoint_text).note_bytes
    anchors_evidence, policy, _header_time = _working_ots_evidence(note_bytes)
    anchored_evidence = bundle.evidence()
    anchored_evidence["anchors"] = anchors_evidence
    anchored = _evaluate(bundle, anchored_evidence, policy=policy)

    horizon_policy = anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=1)
    capped = _evaluate(bundle, bundle.evidence(), policy=horizon_policy)

    for result in (base, consistent, anchored, capped):
        assert result.corroboration != transparency.CORROBORATION_WITNESSED


# --------------------------------------------------------------------------
# Task 5: verify() integration — transparency/corroboration/manifest_freshness.
#
# End-to-end through `verify()`, not just `evaluate_transparency` directly:
# these tests build real receipts (via `issue.issue`) and real key manifests
# (via `manifests.build_key_manifest`/`rotate_key_manifest`), then exercise
# the new `transparency`/`log_keys`/`anchor_policy` kwargs and the three new
# result components together with the pre-existing ones — the property under
# test is specifically that corroboration is a side-channel that can never
# change `signature`/`schema`/`trust`/`ok`.
# --------------------------------------------------------------------------

_RECEIPT_ISSUER = "store.example.com"
_RECEIPT_KID = f"{_RECEIPT_ISSUER}/keys/test#ed25519-1"
_RECEIPT_KP = keys.from_seed(bytes([77]) * 32)


def _receipt_manifest(
    kid: str = _RECEIPT_KID,
    kp: keys.SigningKeyPair = _RECEIPT_KP,
    status: str = "active",
    manifest_version: int = 1,
) -> dict[str, Any]:
    entries = [manifests.key_entry(kid, kp.pub, "2026-01-01T00:00:00Z", None, status)]
    return manifests.build_key_manifest(
        _RECEIPT_ISSUER, manifest_version, "2026-01-01T00:00:00Z", entries, kp, kid
    )


def _receipt_envelope(
    kid: str = _RECEIPT_KID, kp: keys.SigningKeyPair = _RECEIPT_KP
) -> dict[str, Any]:
    payload = make_payload(issuer={"id": _RECEIPT_ISSUER, "display_name": "Example Games Store"})
    return issue.issue(payload, kp, kid)


def _receipt_trust_store(
    manifest: dict[str, Any],
    provenance: str = "tls",
    chains: dict[str, list[dict[str, Any]]] | None = None,
) -> verify.TrustStore:
    return verify.TrustStore(
        manifests={_RECEIPT_ISSUER: manifest},
        provenance={_RECEIPT_ISSUER: provenance},
        chains=chains or {},
    )


def _envelope_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canon.canonical_bytes(manifest)).hexdigest()


def _single_entry_evidence(
    entry: dict[str, Any], hk: pq.HybridSigningKeys, origin: str = ORIGIN, name: str = LOG_NAME
) -> tuple[dict[str, Any], tlog.LogKey, int]:
    """A minimal one-leaf log holding exactly `entry` — trivial (empty)
    inclusion proof, `tree_size=1`. Returns `(evidence, log_key, tree_size)`."""
    leaf_bytes = tlog.encode_entry(entry)
    root = tlog.build_tree([leaf_bytes])
    checkpoint_text = tlog.sign_checkpoint(origin, 1, root, hk, name)
    evidence = {
        "entry": dict(entry),
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": [],
        "checkpoint": checkpoint_text,
    }
    return evidence, _log_key(hk, origin, name), 1


def _bundle_with_entry(entry: dict[str, Any]) -> _Bundle:
    """A 3-leaf `_Bundle` whose entry-under-test (index 1) is `entry`
    instead of the generic fixture entry — reused for the equivocation
    construction, which needs a real 3-leaf tree to fork against."""
    bundle = _Bundle()
    bundle.entries[1] = entry
    bundle.leaves = [tlog.encode_entry(e) for e in bundle.entries]
    bundle.root = tlog.build_tree(bundle.leaves)
    bundle.proof = tlog.inclusion_proof(bundle.leaves, 1)
    bundle.checkpoint_text = tlog.sign_checkpoint(ORIGIN, 3, bundle.root, bundle.hk, LOG_NAME)
    bundle.entry = entry
    return bundle


def test_verify_transparency_defaults_to_not_checked_when_evidence_absent() -> None:
    envelope = _receipt_envelope()
    result = verify.verify(_envelope_bytes(envelope), _receipt_trust_store(_receipt_manifest()))
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.manifest_freshness == "not_checked"
    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == ()


def test_verify_valid_receipt_claim_reports_logged() -> None:
    envelope = _receipt_envelope()
    core_hash = tlog.receipt_core_hash(envelope)
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(_receipt_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.manifest_freshness == "not_checked"  # a receipt claim, not a key-manifest claim
    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == ()


def test_verify_valid_key_manifest_claim_reports_logged_and_freshness() -> None:
    manifest = _receipt_manifest()
    envelope = _receipt_envelope()
    entry = {
        "type": "key-manifest",
        "issuer": _RECEIPT_ISSUER,
        "manifest_version": 1,
        "manifest_sha256": _manifest_sha256(manifest),
    }
    evidence, log_key, tree_size = _single_entry_evidence(entry, _hybrid_keys())

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(manifest),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.manifest_freshness == f"verified_as_of:{tree_size}"
    assert result.signature == "valid"
    assert result.ok is True
    assert result.warnings == ()


def test_verify_payload_only_precommit_hash_is_rejected_as_entry_mismatch() -> None:
    # Vector 28l's property: an old v1-style hash over JCS(payload) ALONE
    # (no signature bytes) must NOT be accepted as receipt existence proof.
    envelope = _receipt_envelope()
    payload_only_hash = hashlib.sha256(canon.canonical_bytes(envelope["payload"])).hexdigest()
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": payload_only_hash}
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(_receipt_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ("transparency_entry_mismatch",)
    assert result.signature == "valid"  # the receipt itself is unaffected
    assert result.ok is True


def test_verify_compromised_key_receipt_stays_invalid_despite_logged_transparency() -> None:
    # design fix 6 / vector 28i's property: corroboration must never rescue
    # an otherwise-rejected receipt — fail-closed stays intact even though
    # the transparency evidence genuinely, verifiably stands.
    envelope = _receipt_envelope()
    compromised_manifest = _receipt_manifest(status="compromised")
    core_hash = tlog.receipt_core_hash(envelope)
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(compromised_manifest),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.signature == "invalid"
    assert result.ok is False
    assert any("compromised" in e for e in result.errors)
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    # The one warning that IS owed: v0.2 §19.4 row 2 keys
    # `compromise_rescue_requires_anchored_receipt` on the VERIFIER being
    # Stage-2-capable and the receipt having no anchored standing, with
    # `D = any` — it does not ask whether a compromise view was supplied, and
    # row 1's explicit "no new warning" for non-Stage-2 verifiers proves the
    # contrast is deliberate. Leaf 28i's oracle pins the same warning; the
    # TypeScript twin in verifiers/ts/test/transparency.test.ts asserts it too.
    assert result.warnings == (verify._WARN_COMPROMISE_RESCUE_REQUIRES_ANCHORED_RECEIPT,)


def test_verify_manifest_v5_without_rotation_chain_caps_corroboration_to_none() -> None:
    manifest = _receipt_manifest(manifest_version=1)
    signing_kp, signing_kid = _RECEIPT_KP, _RECEIPT_KID
    for version in range(2, 6):
        new_kp = keys.generate()
        new_kid = f"{_RECEIPT_ISSUER}/keys/test#ed25519-{version}"
        new_entry = manifests.key_entry(new_kid, new_kp.pub, "2026-01-01T00:00:00Z")
        manifest = manifests.rotate_key_manifest(
            manifest, signing_kp, signing_kid, "2026-01-01T00:00:00Z", new_entry=new_entry
        )
        signing_kp, signing_kid = new_kp, new_kid
    assert manifest["manifest_version"] == 5

    envelope = _receipt_envelope(kid=signing_kid, kp=signing_kp)
    # No `chains` entry supplied at all — the rotation chain back to v1 is omitted.
    trust_store = _receipt_trust_store(manifest)
    entry = {
        "type": "key-manifest",
        "issuer": _RECEIPT_ISSUER,
        "manifest_version": 5,
        "manifest_sha256": _manifest_sha256(manifest),
    }
    evidence, log_key, tree_size = _single_entry_evidence(entry, _hybrid_keys())

    result = verify.verify(
        _envelope_bytes(envelope),
        trust_store,
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.manifest_freshness == f"verified_as_of:{tree_size}"
    assert result.warnings == ("corroboration_requires_rotation_chain",)
    assert result.signature == "valid"
    assert result.ok is True


def test_verify_manifest_v5_with_verified_rotation_chain_keeps_corroboration_logged() -> None:
    # Counterpart of the above: an unbroken, continuous chain back to v1
    # held in the trust store must NOT trigger the rotation-chain cap.
    manifest_v1 = _receipt_manifest(manifest_version=1)
    chain = [manifest_v1]
    manifest = manifest_v1
    signing_kp, signing_kid = _RECEIPT_KP, _RECEIPT_KID
    for version in range(2, 6):
        new_kp = keys.generate()
        new_kid = f"{_RECEIPT_ISSUER}/keys/test#ed25519-{version}"
        new_entry = manifests.key_entry(new_kid, new_kp.pub, "2026-01-01T00:00:00Z")
        manifest = manifests.rotate_key_manifest(
            manifest, signing_kp, signing_kid, "2026-01-01T00:00:00Z", new_entry=new_entry
        )
        chain.append(manifest)
        signing_kp, signing_kid = new_kp, new_kid
    assert manifest["manifest_version"] == 5

    envelope = _receipt_envelope(kid=signing_kid, kp=signing_kp)
    trust_store = _receipt_trust_store(manifest, chains={_RECEIPT_ISSUER: chain})
    entry = {
        "type": "key-manifest",
        "issuer": _RECEIPT_ISSUER,
        "manifest_version": 5,
        "manifest_sha256": _manifest_sha256(manifest),
    }
    evidence, log_key, tree_size = _single_entry_evidence(entry, _hybrid_keys())

    result = verify.verify(
        _envelope_bytes(envelope),
        trust_store,
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.manifest_freshness == f"verified_as_of:{tree_size}"
    assert result.warnings == ()


def test_verify_equivocation_detected_warns_but_leaves_ok_unaffected() -> None:
    envelope = _receipt_envelope()
    core_hash = tlog.receipt_core_hash(envelope)
    receipt_entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    bundle = _bundle_with_entry(receipt_entry)

    # Same fork construction as test_evaluate_transparency_detects_equivocation_
    # on_inconsistent_prior: a REAL extension proof for a different tree,
    # presented against the bundle's actual (unrelated) current root.
    other_entries = _entries(2, salt="fork-prefix")
    other_leaves = [tlog.encode_entry(e) for e in other_entries]
    prior_root = tlog.build_tree(other_leaves)
    extended_leaves = [*other_leaves, bundle.leaves[2]]
    real_extension_proof = tlog.consistency_proof(extended_leaves, 2)
    prior_text = tlog.sign_checkpoint(ORIGIN, 2, prior_root, bundle.hk, LOG_NAME)

    evidence = bundle.evidence()
    evidence["prior_checkpoint"] = prior_text
    evidence["consistency_proof"] = [p.hex() for p in real_extension_proof]

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(_receipt_manifest()),
        transparency=evidence,
        log_keys=bundle.log_keys(),
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_EQUIVOCATION_DETECTED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ("log_equivocation_detected",)
    assert result.signature == "valid"
    assert result.ok is True  # equivocation is informational — never an error


def test_verify_transparency_evidence_without_config_warns_config_missing() -> None:
    envelope = _receipt_envelope()
    core_hash = tlog.receipt_core_hash(envelope)
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    evidence, _log_key_unused, _tree_size = _single_entry_evidence(entry, _hybrid_keys())

    result = verify.verify(
        _envelope_bytes(envelope), _receipt_trust_store(_receipt_manifest()), transparency=evidence
    )
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ("transparency_config_missing",)
    assert result.signature == "valid"
    assert result.ok is True


def test_verify_unrecognized_claim_type_reports_not_checked() -> None:
    envelope = _receipt_envelope()
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": "a" * 64}
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())
    evidence["entry"]["type"] = "unknown-claim-type"
    # tlog.encode_entry only accepts "key-manifest"/"receipt", so a bogus type
    # also fails the log's own closed-schema check — a distinct path from a
    # mismatched hash, still landing on not_checked either way.

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(_receipt_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.warnings == ("transparency_claim_unresolvable",)


def test_verify_raises_transparency_error_on_log_keys_with_disagreeing_origins() -> None:
    envelope = _receipt_envelope()
    core_hash = tlog.receipt_core_hash(envelope)
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())
    other_key = _log_key(_hybrid_keys(), origin="different-log/2026")

    with pytest.raises(transparency.TransparencyError):
        verify.verify(
            _envelope_bytes(envelope),
            _receipt_trust_store(_receipt_manifest()),
            transparency=evidence,
            log_keys=[log_key, other_key],
            anchor_policy=_no_horizon_policy(),
        )


def test_verify_confines_hostile_transparency_evidence_materialization() -> None:
    # JCS materialization is verify()'s sole untrusted-evidence touch, and it
    # now copies the value's OWN data before canonicalizing.
    #
    # Expectation updated when that copy landed: this case used to pin
    # DEGRADATION (`not_checked` plus an unresolvable-claim warning), because
    # the hostile `get` raised on the way in. It is the MECHANISM that changed,
    # not the promise: 18.4 refuses no value for BEING a subtype, so the
    # genuine evidence underneath a hostile accessor is copied out and
    # EVALUATED, and the accessor is never called at all. The property this
    # pins is that the hostile spelling decides nothing -- it can neither crash
    # the integration nor suppress evidence that is genuinely there.
    envelope = _receipt_envelope()
    core_hash = tlog.receipt_core_hash(envelope)
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    base_evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())
    hostile_evidence = _GetRaisesDict(base_evidence)

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(_receipt_manifest()),
        transparency=hostile_evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == "logged"
    assert result.warnings == ()
    assert result.signature == "valid"
    assert result.ok is True


def test_verify_existing_callers_are_unaffected_by_new_keyword_only_params() -> None:
    # Zero-behavior-change guarantee: a caller that never passes the three
    # new kwargs sees exactly the pre-Task-5 result shape/values, just with
    # the three new components at their documented defaults.
    envelope = issue.issue(make_payload(), _RECEIPT_KP, _RECEIPT_KID)
    result = verify.verify(_envelope_bytes(envelope), _receipt_trust_store(_receipt_manifest()))
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.revocation == "unknown"
    assert result.binding == "not_checked"
    assert result.trust == "verified"
    assert result.transparency == "not_checked"
    assert result.corroboration == "none"
    assert result.manifest_freshness == "not_checked"
    assert result.ok is True
    assert result.warnings == ()


def test_verify_materializes_changing_tree_size_once_before_evaluation() -> None:
    # Without materialization, verify() read 777 here, evaluator verified 1,
    # then manifest freshness was reported as the attacker-selected 777.
    manifest = _receipt_manifest()
    envelope = _receipt_envelope()
    entry = {
        "type": "key-manifest",
        "issuer": _RECEIPT_ISSUER,
        "manifest_version": 1,
        "manifest_sha256": _manifest_sha256(manifest),
    }
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())
    changing_evidence = _TreeSizeChangesDict(evidence)

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(manifest),
        transparency=changing_evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    # Expectation updated when the own-data copy landed. This used to pin that
    # the changing value was read exactly ONCE, so a mismatch was reported
    # instead of freshness for a later value: the time-of-check/time-of-use gap
    # was made harmless by narrowing it to a single read. The copy removes the
    # gap entirely -- the hostile accessor is never consulted (ZERO reads), the
    # value's own data is what reaches the evaluator, and there is no longer a
    # mismatch to report because there is no longer a second value. Fewer
    # reads is the stronger property, not a weaker one: a defence that has to
    # read a hostile value exactly once still depends on counting reads.
    assert changing_evidence.tree_size_reads == 0
    assert result.transparency == "logged"
    assert result.manifest_freshness == "verified_as_of:1"
    assert result.warnings == ()
    assert result.signature == "valid"
    assert result.ok is True


def test_verify_materializes_claim_type_before_post_evaluation_comparison() -> None:
    # The old integration compared this object twice while resolving its type,
    # then a third time after evaluation while setting freshness; the third
    # comparison escaped verify(). JCS materialization replaces it with plain
    # str before any claim-phase comparison.
    manifest = _receipt_manifest()
    envelope = _receipt_envelope()
    entry = {
        "type": "key-manifest",
        "issuer": _RECEIPT_ISSUER,
        "manifest_version": 1,
        "manifest_sha256": _manifest_sha256(manifest),
    }
    evidence, log_key, tree_size = _single_entry_evidence(entry, _hybrid_keys())
    claim_type = _RaisesOnThirdEqualityString("key-manifest")
    evidence["entry"]["type"] = claim_type

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(manifest),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert claim_type.comparisons == 0
    assert result.transparency == transparency.TRANSPARENCY_LOGGED
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    assert result.manifest_freshness == f"verified_as_of:{tree_size}"
    assert result.warnings == ()
    assert result.signature == "valid"
    assert result.ok is True


def test_verify_caps_oversized_transparency_evidence() -> None:
    envelope = _receipt_envelope()
    core_hash = tlog.receipt_core_hash(envelope)
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())
    evidence["padding"] = "x" * verify._MAX_TRANSPARENCY_EVIDENCE_LEN

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(_receipt_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=_no_horizon_policy(),
    )
    assert result.transparency == transparency.TRANSPARENCY_NOT_CHECKED
    assert result.corroboration == transparency.CORROBORATION_NONE
    assert result.manifest_freshness == "not_checked"
    assert result.warnings == ("transparency_claim_unresolvable",)
    assert result.signature == "valid"
    assert result.ok is True


def test_verify_accepts_evaluator_max_scale_anchor_evidence() -> None:
    # Harmonization guard (review finding): the outer materialization cap
    # must COVER what the anchor evaluator's own inner caps accept. The
    # binding inner constraint is the per-chain operand TOTAL, not
    # `_MAX_OPS_PER_PROOF * _MAX_OP_HEX_LEN` — that product is 268,435,456
    # operand characters and would overshoot the 10,000,000-character outer
    # ceiling by ~258,000,000 characters, which is exactly why the total cap
    # exists (see anchor._MAX_TOTAL_OP_HEX_LEN). 64 OTS proofs each
    # carrying operands summing to that total serialize past 4M chars and must
    # still verify end-to-end — never degrade to
    # transparency_claim_unresolvable as a false negative.
    envelope = _receipt_envelope()
    core_hash = tlog.receipt_core_hash(envelope)
    entry = {"type": "receipt", "issuer": _RECEIPT_ISSUER, "core_sha256": core_hash}
    evidence, log_key, _tree_size = _single_entry_evidence(entry, _hybrid_keys())

    note_bytes = tlog.parse_checkpoint(evidence["checkpoint"]).note_bytes
    header_time = 1700000000
    header_hash = "3a" * 32
    operand_hex = "ab" * (anchor._MAX_OP_HEX_LEN // 2)
    operand = bytes.fromhex(operand_hex)
    acc = hashlib.sha256(note_bytes).digest()
    ops: list[list[str]] = []
    # Exactly at the worst case the evaluator admits, on BOTH binding axes:
    # maximal operands until the operand TOTAL is spent, then empty-operand
    # ops until the op COUNT is spent too. Asserting `<=` on either axis
    # would let the bundle sit under the worst case and still pass, which is
    # how a harmonization test stops harmonizing. Derived from the constants
    # so a future cap change re-derives the bundle rather than under-testing.
    non_empty_operands, remainder = divmod(anchor._MAX_TOTAL_OP_HEX_LEN, anchor._MAX_OP_HEX_LEN)
    assert remainder == 0
    assert 2 * non_empty_operands <= anchor._MAX_OPS_PER_PROOF
    for _ in range(non_empty_operands):
        ops.append(["prepend", operand_hex])
        ops.append(["sha256"])
        acc = hashlib.sha256(operand + acc).digest()
    while len(ops) < anchor._MAX_OPS_PER_PROOF:
        ops.append(["prepend", ""])
    assert sum(len(op[1]) for op in ops if len(op) == 2) == anchor._MAX_TOTAL_OP_HEX_LEN
    assert len(ops) == anchor._MAX_OPS_PER_PROOF
    proof = {
        "kind": "ots",
        "ops": ops,
        "header_merkle_root": acc.hex(),
        "header_time": header_time,
        "header_hash": header_hash,
    }
    evidence["anchors"] = {
        "checkpoint": evidence["checkpoint"],
        "proofs": [proof] * anchor._MAX_PROOFS_PER_EVIDENCE,
    }
    serialized_len = len(canon.dumps(evidence))
    assert serialized_len > anchor._MAX_PROOFS_PER_EVIDENCE * anchor._MAX_TOTAL_OP_HEX_LEN
    assert serialized_len <= verify._MAX_TRANSPARENCY_EVIDENCE_LEN

    pinned = anchor.PinnedHeader(header_hash=header_hash, merkle_root=acc.hex(), time=header_time)
    policy = anchor.AnchorPolicy(pinned_headers={header_hash: pinned}, crqc_horizon=None)

    result = verify.verify(
        _envelope_bytes(envelope),
        _receipt_trust_store(_receipt_manifest()),
        transparency=evidence,
        log_keys=[log_key],
        anchor_policy=policy,
    )
    assert result.transparency == "anchored_before:2023-11-14T22:13:20Z"
    assert result.corroboration == transparency.CORROBORATION_LOGGED
    # No `anchor_profile` on this evidence -> legacy note-bytes-only
    # commitment, flagged (still fully verifiable, G4 eternal verifiability).
    assert result.warnings == ("anchor_note_only",)
    assert result.signature == "valid"
    assert result.ok is True
