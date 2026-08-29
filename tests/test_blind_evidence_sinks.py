"""Adversarial tests for caller-owned evidence admission through verify()."""

from __future__ import annotations

import dataclasses
import json
import multiprocessing as mp
import queue
import time
import traceback
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from attest import anchor, canon, issue, keys, manifests, pq, revocation, tlog, transfer, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/test#ed25519-1"
ISSUER_KP = keys.from_seed(bytes([91]) * 32)
HOLDER_KP = keys.from_seed(bytes([92]) * 32)
NEW_HOLDER_KP = keys.from_seed(bytes([93]) * 32)

OLD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
NEW_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
LATE_NEW_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAX"
AT = "2026-07-23T00:00:00Z"
NEW_HOLDER_PUBKEY = keys.b64u(NEW_HOLDER_KP.pub)

LOG_ORIGIN = "evidence-sink-log.attest.example/2026"
LOG_NAME = "attest-evidence-sink-log-1"
LOG_KEYS = pq.HybridSigningKeys(ed=keys.from_seed(bytes([94]) * 32), mldsa=pq.generate())


@dataclasses.dataclass(frozen=True)
class ResultSnapshot:
    signature: str
    schema: str
    revocation: str
    binding: str
    trust: str
    transparency: str
    corroboration: str
    manifest_freshness: str
    ok: bool
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


class _NeverYieldingDict(dict[str, Any]):
    def __iter__(self) -> Any:
        while True:
            time.sleep(3600)
            yield "never"


class _NeverYieldingList(list[Any]):
    def __iter__(self) -> Any:
        while True:
            time.sleep(3600)
            yield None


class _NeverYieldingString(str):
    def __iter__(self) -> Any:
        while True:
            time.sleep(3600)
            yield "x"


class _InjectingInt(int):
    text: str

    def __new__(cls, value: int, text: str) -> _InjectingInt:
        instance = int.__new__(cls, value)
        instance.text = text
        return instance

    def __str__(self) -> str:
        return self.text


class _ShadowKey(str):
    def __hash__(self) -> int:
        return id(self)

    def __eq__(self, other: object) -> bool:
        return self is other


def _key_manifest() -> dict[str, Any]:
    entries = [manifests.key_entry(KID, ISSUER_KP.pub, "2026-01-01T00:00:00Z", None, "active")]
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", entries, ISSUER_KP, KID)


def _trust_store() -> verify.TrustStore:
    return verify.TrustStore(manifests={ISSUER: _key_manifest()}, provenance={ISSUER: "tls"})


def _wire(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _payload(
    *,
    revocability: str = "none",
    not_transferable_before: str | None = None,
) -> dict[str, Any]:
    license_block: dict[str, Any] = {"revocability": revocability}
    if revocability == "refund_window":
        license_block["revocation_window_days"] = 14
    if not_transferable_before is not None:
        license_block["not_transferable_before"] = not_transferable_before
    return make_payload(
        receipt_id=OLD_ID,
        issuer={"id": ISSUER, "display_name": "Example Store"},
        buyer={"pubkey": keys.b64u(HOLDER_KP.pub)},
        license=license_block,
    )


def _envelope(*, revocability: str = "none") -> dict[str, Any]:
    return issue.issue(_payload(revocability=revocability), ISSUER_KP, KID)


def _log_key() -> tlog.LogKey:
    return tlog.LogKey(
        origin=LOG_ORIGIN,
        name=LOG_NAME,
        ed25519_pub=LOG_KEYS.ed.pub,
        mldsa_pub=LOG_KEYS.mldsa.pub,
    )


def _no_horizon_policy() -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


def _single_entry_evidence(entry: dict[str, Any]) -> dict[str, Any]:
    leaf = tlog.encode_entry(entry)
    checkpoint = tlog.sign_checkpoint(LOG_ORIGIN, 1, tlog.build_tree([leaf]), LOG_KEYS, LOG_NAME)
    return {
        "entry": dict(entry),
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": [],
        "checkpoint": checkpoint,
    }


def _receipt_transparency_evidence(envelope: dict[str, Any]) -> dict[str, Any]:
    return _single_entry_evidence(
        {
            "type": "receipt",
            "issuer": ISSUER,
            "core_sha256": tlog.receipt_core_hash(envelope),
        }
    )


def _transfer_record(new_receipt_id: str = NEW_ID) -> dict[str, Any]:
    sig = transfer.sign_authorization(OLD_ID, NEW_HOLDER_PUBKEY, AT, HOLDER_KP)
    return transfer.build_record(OLD_ID, new_receipt_id, NEW_HOLDER_PUBKEY, AT, sig, ISSUER_KP, KID)


def _transfer_claim(new_receipt_id: str = NEW_ID) -> dict[str, Any]:
    record = _transfer_record(new_receipt_id)
    evidence = _single_entry_evidence(
        {"type": "transfer-record", "issuer": ISSUER, "record_sha256": transfer.record_hash(record)}
    )
    return {"record": record, "evidence": evidence}


def _transferred_revocation_record() -> dict[str, Any]:
    return revocation.build_record(OLD_ID, "transferred", AT, ISSUER_KP, KID)


def _refund_window_revocation_record() -> dict[str, Any]:
    return revocation.build_record(OLD_ID, "revoked", "2026-07-03T00:00:00Z", ISSUER_KP, KID)


def _duplicate_member(
    name: str,
    first: Any,
    second: Any,
    *,
    shadow_first: bool,
) -> dict[str, Any]:
    shadow = _ShadowKey(name)
    if shadow_first:
        return {shadow: first, name: second}
    return {name: first, shadow: second}


def _deep_array(depth: int) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth):
        value = [value]
    return value


def _snapshot(result: verify.VerificationResult) -> ResultSnapshot:
    return ResultSnapshot(
        signature=result.signature,
        schema=result.schema,
        revocation=result.revocation,
        binding=result.binding,
        trust=result.trust,
        transparency=result.transparency,
        corroboration=result.corroboration,
        manifest_freshness=result.manifest_freshness,
        ok=result.ok,
        warnings=tuple(result.warnings),
        errors=tuple(result.errors),
    )


def _verify_transfer_with_claims(claims: list[Any]) -> verify.VerificationResult:
    return verify.verify(
        _wire(_envelope(revocability="policy")),
        _trust_store(),
        revocation_view=[_transferred_revocation_record()],
        transfer_view=claims,  # type: ignore[arg-type]
        log_keys=[_log_key()],
        anchor_policy=_no_horizon_policy(),
    )


def _bad_transfer_claim(kind: str) -> Any:
    if kind == "wrong-type":
        return "not a claim"
    if kind == "missing-record":
        return {
            "evidence": _single_entry_evidence(
                {"type": "transfer-record", "issuer": ISSUER, "record_sha256": "0" * 64}
            )
        }
    if kind == "truncated-record":
        return {"record": {"receipt_id": OLD_ID}, "evidence": None}
    if kind == "missing-evidence":
        return {"record": _transfer_record(), "evidence": None}
    if kind == "float-record":
        return {"record": 1.5, "evidence": None}
    if kind == "out-of-range-record":
        return {"record": 2**53, "evidence": None}
    if kind == "over-depth-record":
        return {"record": _deep_array(canon.MAX_DEPTH + 2), "evidence": None}
    if kind == "duplicate-record-member":
        valid = _transfer_record()
        bad_record = _duplicate_member(
            "receipt_id", "01ARZ3NDEKTSV4RRFFQ69G5FQ0", OLD_ID, shadow_first=True
        )
        for key, value in valid.items():
            if key != "receipt_id":
                bad_record[key] = value
        return {"record": bad_record, "evidence": _transfer_claim()["evidence"]}
    raise AssertionError(f"unknown mutation kind: {kind}")


def _case_transparency_never_yielding_mapping() -> ResultSnapshot:
    return _snapshot(
        verify.verify(
            _wire(_envelope()),
            _trust_store(),
            transparency=_NeverYieldingDict(),
            log_keys=[_log_key()],
            anchor_policy=_no_horizon_policy(),
        )
    )


def _case_refund_window_revocation_evidence_never_yielding_mapping() -> ResultSnapshot:
    return _snapshot(
        verify.verify(
            _wire(_envelope(revocability="refund_window")),
            _trust_store(),
            revocation_view=[_refund_window_revocation_record()],
            revocation_evidence=_NeverYieldingDict(),
            log_keys=[_log_key()],
            anchor_policy=_no_horizon_policy(),
        )
    )


def _case_transfer_view_never_yielding_list() -> ResultSnapshot:
    return _snapshot(
        verify.verify(
            _wire(_envelope(revocability="policy")),
            _trust_store(),
            revocation_view=[_transferred_revocation_record()],
            transfer_view=_NeverYieldingList(),
            log_keys=[_log_key()],
            anchor_policy=_no_horizon_policy(),
        )
    )


def _case_transparency_checkpoint_never_yielding_string() -> ResultSnapshot:
    envelope = _envelope()
    evidence = _receipt_transparency_evidence(envelope)
    evidence["checkpoint"] = _NeverYieldingString(evidence["checkpoint"])
    return _snapshot(
        verify.verify(
            _wire(envelope),
            _trust_store(),
            transparency=evidence,
            log_keys=[_log_key()],
            anchor_policy=_no_horizon_policy(),
        )
    )


def _case_transparency_int_text_injection() -> ResultSnapshot:
    envelope = _envelope()
    evidence = _receipt_transparency_evidence(envelope)
    evidence["tree_size"] = _InjectingInt(1, '1,"leaf_index":777')
    return _snapshot(
        verify.verify(
            _wire(envelope),
            _trust_store(),
            transparency=evidence,
            log_keys=[_log_key()],
            anchor_policy=_no_horizon_policy(),
        )
    )


def _case_transparency_duplicate_member(shadow_first: bool) -> ResultSnapshot:
    envelope = _envelope()
    valid = _receipt_transparency_evidence(envelope)
    evidence = _duplicate_member(
        "entry",
        valid["entry"],
        {"type": "receipt", "issuer": ISSUER, "core_sha256": "0" * 64},
        shadow_first=shadow_first,
    )
    for key, value in valid.items():
        if key != "entry":
            evidence[key] = value
    return _snapshot(
        verify.verify(
            _wire(envelope),
            _trust_store(),
            transparency=evidence,
            log_keys=[_log_key()],
            anchor_policy=_no_horizon_policy(),
        )
    )


def _case_revocation_evidence_duplicate_member(shadow_first: bool) -> ResultSnapshot:
    record = _refund_window_revocation_record()
    valid = _single_entry_evidence(
        {
            "type": "revocation-record",
            "issuer": ISSUER,
            "record_sha256": revocation.record_hash(record),
        }
    )
    evidence = _duplicate_member(
        "entry",
        valid["entry"],
        {"type": "revocation-record", "issuer": ISSUER, "record_sha256": "0" * 64},
        shadow_first=shadow_first,
    )
    for key, value in valid.items():
        if key != "entry":
            evidence[key] = value
    return _snapshot(
        verify.verify(
            _wire(_envelope(revocability="refund_window")),
            _trust_store(),
            revocation_view=[record],
            revocation_evidence=evidence,
            log_keys=[_log_key()],
            anchor_policy=_no_horizon_policy(),
        )
    )


def _case_duplicate_transfer_claim_cannot_back(shadow_first: bool) -> ResultSnapshot:
    valid_claim = _transfer_claim()
    invalid_record = {"receipt_id": OLD_ID, "new_receipt_id": LATE_NEW_ID}
    claim = _duplicate_member(
        "record", valid_claim["record"], invalid_record, shadow_first=shadow_first
    )
    claim["evidence"] = valid_claim["evidence"]
    return _snapshot(_verify_transfer_with_claims([claim]))


def _case_duplicate_nested_transfer_record_cannot_back(shadow_first: bool) -> ResultSnapshot:
    valid_claim = _transfer_claim()
    record = _duplicate_member(
        "new_receipt_id",
        valid_claim["record"]["new_receipt_id"],
        LATE_NEW_ID,
        shadow_first=shadow_first,
    )
    for key, value in valid_claim["record"].items():
        if key != "new_receipt_id":
            record[key] = value
    return _snapshot(
        _verify_transfer_with_claims([{"record": record, "evidence": valid_claim["evidence"]}])
    )


def _case_transfer_bad_sibling_survives(kind: str) -> ResultSnapshot:
    return _snapshot(_verify_transfer_with_claims([_bad_transfer_claim(kind), _transfer_claim()]))


def _case_transfer_only_bad_sibling(kind: str) -> ResultSnapshot:
    return _snapshot(_verify_transfer_with_claims([_bad_transfer_claim(kind)]))


_CASES: dict[str, Callable[..., ResultSnapshot]] = {
    "transparency_never_yielding_mapping": _case_transparency_never_yielding_mapping,
    "refund_window_revocation_evidence_never_yielding_mapping": (
        _case_refund_window_revocation_evidence_never_yielding_mapping
    ),
    "transfer_view_never_yielding_list": _case_transfer_view_never_yielding_list,
    "transparency_checkpoint_never_yielding_string": (
        _case_transparency_checkpoint_never_yielding_string
    ),
    "transparency_int_text_injection": _case_transparency_int_text_injection,
    "transparency_duplicate_member": _case_transparency_duplicate_member,
    "revocation_evidence_duplicate_member": _case_revocation_evidence_duplicate_member,
    "duplicate_transfer_claim_cannot_back": _case_duplicate_transfer_claim_cannot_back,
    "duplicate_nested_transfer_record_cannot_back": (
        _case_duplicate_nested_transfer_record_cannot_back
    ),
    "transfer_bad_sibling_survives": _case_transfer_bad_sibling_survives,
    "transfer_only_bad_sibling": _case_transfer_only_bad_sibling,
}


def _run_case(name: str, *args: Any, timeout: float = 4.0) -> ResultSnapshot:
    ctx = mp.get_context("fork")
    results: mp.Queue[tuple[str, Any]] = ctx.Queue()

    def target() -> None:
        try:
            results.put(("ok", _CASES[name](*args)))
        except BaseException:
            results.put(("error", traceback.format_exc()))

    process = ctx.Process(target=target)
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.terminate()
        process.join()
        pytest.fail(f"{name}: verify() did not return within {timeout:.1f}s")
    try:
        status, payload = results.get_nowait()
    except queue.Empty:
        pytest.fail(f"{name}: child exited without returning a verify() result")
    if status == "error":
        pytest.fail(payload)
    return payload


def _assert_valid_receipt(result: ResultSnapshot) -> None:
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.trust == "verified"
    assert result.errors == ()


def _assert_transfer_survived(result: ResultSnapshot) -> None:
    _assert_valid_receipt(result)
    assert result.revocation == "transferred"
    assert result.ok is False


def _assert_only_unbacked_transfer(result: ResultSnapshot) -> None:
    _assert_valid_receipt(result)
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert any(
        warning in result.warnings
        for warning in (
            "transferred_revocation_unbacked",
            "transfer_record_unlogged",
            "transfer_not_yet_transferable",
        )
    )


def test_transparency_evidence_mapping_that_never_yields_returns_not_checked() -> None:
    result = _run_case("transparency_never_yielding_mapping", timeout=1.0)

    _assert_valid_receipt(result)
    assert result.transparency == "not_checked"
    assert result.corroboration == "none"
    assert result.manifest_freshness == "not_checked"
    assert result.ok is True
    assert "transparency_claim_unresolvable" in result.warnings


def test_refund_window_revocation_evidence_mapping_that_never_yields_returns_ignored() -> None:
    result = _run_case("refund_window_revocation_evidence_never_yielding_mapping", timeout=1.0)

    _assert_valid_receipt(result)
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert "revocation_unlogged_deadline" in result.warnings


def test_transfer_view_list_that_never_yields_returns_unbacked() -> None:
    result = _run_case("transfer_view_never_yielding_list", timeout=1.0)

    _assert_only_unbacked_transfer(result)


def test_transparency_string_member_that_never_yields_is_copied_as_plain_string() -> None:
    result = _run_case("transparency_checkpoint_never_yielding_string")

    _assert_valid_receipt(result)
    assert result.transparency == "logged"
    assert result.corroboration == "logged"
    assert result.ok is True


def test_transparency_scalar_text_injection_cannot_change_the_consumed_tree_size() -> None:
    result = _run_case("transparency_int_text_injection")

    _assert_valid_receipt(result)
    assert result.transparency == "logged"
    assert result.corroboration == "logged"
    assert result.ok is True


@pytest.mark.parametrize("shadow_first", [True, False])
def test_transparency_evidence_duplicate_member_name_degrades_not_checked(
    shadow_first: bool,
) -> None:
    result = _run_case("transparency_duplicate_member", shadow_first)

    _assert_valid_receipt(result)
    assert result.transparency == "not_checked"
    assert result.corroboration == "none"
    assert result.ok is True
    assert "transparency_claim_unresolvable" in result.warnings


@pytest.mark.parametrize("shadow_first", [True, False])
def test_revocation_evidence_duplicate_member_name_does_not_honor_refund_window_record(
    shadow_first: bool,
) -> None:
    result = _run_case("revocation_evidence_duplicate_member", shadow_first)

    _assert_valid_receipt(result)
    assert result.revocation == "invalid_revocation_ignored"
    assert result.ok is True
    assert "revocation_unlogged_deadline" in result.warnings


@pytest.mark.parametrize("shadow_first", [True, False])
def test_transfer_claim_duplicate_record_member_is_rejected_not_reduced(
    shadow_first: bool,
) -> None:
    result = _run_case("duplicate_transfer_claim_cannot_back", shadow_first)

    _assert_only_unbacked_transfer(result)


@pytest.mark.parametrize("shadow_first", [True, False])
def test_transfer_claim_nested_duplicate_record_member_is_rejected_not_reduced(
    shadow_first: bool,
) -> None:
    result = _run_case("duplicate_nested_transfer_record_cannot_back", shadow_first)

    _assert_only_unbacked_transfer(result)


@settings(
    deadline=None,
    derandomize=True,
    max_examples=8,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(
    st.sampled_from(
        [
            "wrong-type",
            "missing-record",
            "truncated-record",
            "missing-evidence",
            "float-record",
            "out-of-range-record",
            "over-depth-record",
            "duplicate-record-member",
        ]
    )
)
def test_transfer_view_bad_sibling_is_set_aside_alone_for_profile_boundary_mutations(
    kind: str,
) -> None:
    result = _run_case("transfer_bad_sibling_survives", kind)

    _assert_transfer_survived(result)


@pytest.mark.parametrize(
    "kind",
    ["truncated-record", "missing-evidence", "float-record", "out-of-range-record"],
)
def test_transfer_view_bad_claim_alone_does_not_back_transfer(kind: str) -> None:
    result = _run_case("transfer_only_bad_sibling", kind)

    _assert_only_unbacked_transfer(result)
