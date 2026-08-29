"""Blind adversarial bench for transfer.audit_chain evidence admission.

The cases pin v0.2 section 17.5 plus the universal simple-value boundary from
the Task 16 plan. They build every genuine transfer/revocation side-document
through the public constructors, then wrap caller-supplied views at the audit
surface.
"""

from __future__ import annotations

import copy
import multiprocessing
import queue
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Literal, cast

import pytest

from attest import anchor, keys, manifests, pq, revocation, tlog, transfer

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/audit-chain-blind#ed25519-1"

# TEST ONLY: deterministic keys.
ISSUER_KP = keys.from_seed(bytes([61]) * 32)
OLD_HOLDER_KP = keys.from_seed(bytes([62]) * 32)
NEW_A_HOLDER_KP = keys.from_seed(bytes([63]) * 32)
NEW_B_HOLDER_KP = keys.from_seed(bytes([64]) * 32)

OLD_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
NEW_A_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
NEW_B_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAY"
NEW_C_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
AT = "2026-07-23T00:00:00Z"
AT2 = "2026-07-24T00:00:00Z"

TRANSFER_LOG_ORIGIN = "transfer-log.attest.example/blind-audit"
TRANSFER_LOG_NAME = "attest-transfer-log-blind-audit"

ERR_NO_TRANSFER_RECORD = "chain link 1: no transfer record"
ERR_ISSUER_SIGNATURE_INVALID = "chain link 1: issuer signature invalid"
ERR_HOLDER_AUTHORIZATION_INVALID = "chain link 1: holder authorization invalid"
ERR_TRANSFER_RECORD_NOT_LOGGED = "chain link 1: transfer record not logged"
ERR_NOT_TRANSFERABLE_BEFORE = "chain link 1: transferred before not_transferable_before"
ERR_LOSING_BRANCH = "chain link 1: losing branch of a double assignment"
ERR_LOOP_CLOSURE = "chain link 1: new receipt buyer.pubkey != new_holder_pubkey"
ERR_MISSING_BACKED_REVOCATION = (
    "chain link 1: previous receipt lacks a backed transferred-class revocation"
)

DIRECT_WALL_SECONDS = 2.0
SUBPROCESS_WALL_SECONDS = 5.0

type ContainerCase = Literal["none", "dict", "hostile_dict", "generator"]
type RailName = Literal["transfer", "revocation"]
type InfiniteCase = Literal["infinite_transfer", "infinite_revocation"]
type MalformedCase = Literal[
    "previous_receipt_id_wrong_type",
    "previous_buyer_wrong_type",
    "previous_not_transferable_before_wrong_type",
    "next_receipt_id_missing",
    "next_buyer_pubkey_wrong_type",
    "claim_record_missing",
    "claim_record_wrong_type",
    "claim_evidence_wrong_type",
    "evidence_leaf_index_out_of_range",
    "transfer_record_receipt_id_wrong_type",
    "transfer_record_new_receipt_id_missing",
    "transfer_record_new_holder_pubkey_missing",
    "transfer_record_transferred_at_out_of_range",
    "transfer_record_signature_missing",
    "revocation_record_receipt_id_wrong_type",
    "revocation_record_status_missing",
    "revocation_record_revoked_at_out_of_range",
    "revocation_record_signature_wrong_type",
]


@dataclass
class AuditArgs:
    payloads: list[dict[str, Any]]
    transfer_view: object
    revocation_view: object
    key_manifest: dict[str, Any]
    log_keys: list[tlog.LogKey]
    anchor_policy: anchor.AnchorPolicy


class IteratesAs(str):
    """A str subclass whose stored value and iterated spelling diverge."""

    _iterated: str

    def __new__(cls, stored: str, iterated: str) -> IteratesAs:
        obj = str.__new__(cls, stored)
        obj._iterated = iterated
        return obj

    def __iter__(self) -> Iterator[str]:
        return iter(self._iterated)


class HostileGetDict(dict[str, Any]):
    """Own dict data is genuine, but dynamic lookup is hostile."""

    def get(self, key: object, default: object = None) -> Any:
        raise RuntimeError(f"hostile get reached for {key!r}")


class HostileTopMapping(dict[str, Any]):
    """A non-list top container that must be degraded without iteration."""

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("hostile top-level mapping iteration reached")


class NeverEndingTransferView(list[dict[str, Any]]):
    """A list subclass whose dynamic iteration never terminates."""

    def __iter__(self) -> Iterator[dict[str, Any]]:
        while True:
            yield {"record": "not a transfer record", "evidence": None}


class NeverEndingRevocationView(list[dict[str, Any]]):
    """A list subclass whose dynamic iteration never terminates."""

    def __iter__(self) -> Iterator[dict[str, Any]]:
        while True:
            yield {"receipt_id": "not-a-ulid", "status": "transferred"}


class SecondPassFreshTransferView(list[dict[str, Any]]):
    """Own list data has one good claim; the second dynamic pass invents one."""

    _passes: int
    _fresh_second_pass_claim: dict[str, Any]

    def __init__(
        self, selected_claim: dict[str, Any], fresh_second_pass_claim: dict[str, Any]
    ) -> None:
        super().__init__([selected_claim])
        self._passes = 0
        self._fresh_second_pass_claim = fresh_second_pass_claim

    def __iter__(self) -> Iterator[dict[str, Any]]:
        self._passes += 1
        if self._passes == 1:
            yield copy.deepcopy(list.__getitem__(self, 0))
            return
        yield copy.deepcopy(self._fresh_second_pass_claim)


class FreshRevocationIterationView(list[dict[str, Any]]):
    """Own list data is empty; dynamic iteration fabricates backing records."""

    _record: dict[str, Any]

    def __init__(self, record: dict[str, Any]) -> None:
        super().__init__([])
        self._record = record

    def __iter__(self) -> Iterator[dict[str, Any]]:
        yield copy.deepcopy(self._record)


def _key_manifest() -> dict[str, Any]:
    entry = manifests.key_entry(KID, ISSUER_KP.pub, "2026-01-01T00:00:00Z", None, "active")
    return manifests.build_key_manifest(ISSUER, 1, "2026-01-01T00:00:00Z", [entry], ISSUER_KP, KID)


def _log_signing_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _transfer_log_key(hk: pq.HybridSigningKeys) -> tlog.LogKey:
    return tlog.LogKey(
        origin=TRANSFER_LOG_ORIGIN,
        name=TRANSFER_LOG_NAME,
        ed25519_pub=hk.ed.pub,
        mldsa_pub=hk.mldsa.pub,
    )


def _anchor_policy() -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


def _payload(receipt_id: object, holder_kp: keys.SigningKeyPair) -> dict[str, Any]:
    return {"receipt_id": receipt_id, "buyer": {"pubkey": keys.b64u(holder_kp.pub)}}


def _transfer_record(
    receipt_id: str = OLD_ID,
    new_receipt_id: str = NEW_A_ID,
    new_holder_kp: keys.SigningKeyPair = NEW_A_HOLDER_KP,
    holder_kp: keys.SigningKeyPair = OLD_HOLDER_KP,
    transferred_at: str = AT,
) -> dict[str, Any]:
    new_holder_pubkey = keys.b64u(new_holder_kp.pub)
    holder_sig = transfer.sign_authorization(
        receipt_id, new_holder_pubkey, transferred_at, holder_kp
    )
    return transfer.build_record(
        receipt_id,
        new_receipt_id,
        new_holder_pubkey,
        transferred_at,
        holder_sig,
        ISSUER_KP,
        KID,
    )


def _transferred_revocation(receipt_id: str = OLD_ID, revoked_at: str = AT) -> dict[str, Any]:
    return revocation.build_record(receipt_id, "transferred", revoked_at, ISSUER_KP, KID)


def _transfer_log_bundle(
    records_in_order: list[dict[str, Any]], hk: pq.HybridSigningKeys
) -> list[dict[str, Any]]:
    entries = [
        {"type": "transfer-record", "issuer": ISSUER, "record_sha256": transfer.record_hash(r)}
        for r in records_in_order
    ]
    leaves = [tlog.encode_entry(entry) for entry in entries]
    root = tlog.build_tree(leaves)
    checkpoint_text = tlog.sign_checkpoint(
        TRANSFER_LOG_ORIGIN, len(leaves), root, hk, TRANSFER_LOG_NAME
    )
    return [
        {
            "entry": entry,
            "leaf_index": index,
            "tree_size": len(leaves),
            "inclusion_proof": [node.hex() for node in tlog.inclusion_proof(leaves, index)],
            "checkpoint": checkpoint_text,
        }
        for index, entry in enumerate(entries)
    ]


def _claim(record: dict[str, Any], evidence: dict[str, Any] | None) -> dict[str, Any]:
    return {"record": record, "evidence": evidence}


def _valid_args() -> AuditArgs:
    hk = _log_signing_keys()
    record = _transfer_record()
    evidence = _transfer_log_bundle([record], hk)[0]
    return AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(NEW_A_ID, NEW_A_HOLDER_KP)],
        transfer_view=[_claim(record, evidence)],
        revocation_view=[_transferred_revocation()],
        key_manifest=_key_manifest(),
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_anchor_policy(),
    )


def _run_audit(
    args: AuditArgs, max_seconds: float = DIRECT_WALL_SECONDS
) -> transfer.ChainAuditResult:
    started = time.perf_counter()
    result = transfer.audit_chain(
        args.payloads,
        cast(Any, args.transfer_view),
        cast(Any, args.revocation_view),
        args.key_manifest,
        args.log_keys,
        args.anchor_policy,
    )
    elapsed = time.perf_counter() - started
    assert elapsed <= max_seconds, (
        f"audit_chain returned after {elapsed:.3f}s, above the {max_seconds:.3f}s wall-clock bound"
    )
    assert isinstance(result, transfer.ChainAuditResult)
    return result


def _assert_valid_single_link(result: transfer.ChainAuditResult) -> None:
    assert result.valid is True
    assert result.link_status == ("valid",)
    assert result.errors == ()


def _assert_invalid_single_link(result: transfer.ChainAuditResult) -> None:
    assert result.valid is False
    assert result.link_status == ("invalid",)


def _assert_error_present(result: transfer.ChainAuditResult, expected: str) -> None:
    assert expected in result.errors, f"expected {expected!r} in {result.errors!r}"


def _single_item_generator(item: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield item


def _bad_top_container(kind: ContainerCase, good_unit: dict[str, Any]) -> object:
    if kind == "none":
        return None
    if kind == "dict":
        return {"unit": good_unit}
    if kind == "hostile_dict":
        return HostileTopMapping({"unit": good_unit})
    if kind == "generator":
        return _single_item_generator(good_unit)
    raise AssertionError(f"unhandled container case {kind!r}")


@pytest.mark.parametrize(
    ("signed_successor", "consumed_successor"),
    [(NEW_A_ID, NEW_B_ID), (NEW_B_ID, NEW_A_ID)],
    ids=["signed_new_a_consumed_new_b", "signed_new_b_consumed_new_a"],
)
def test_audit_chain_rejects_chameleon_successor_permissive_false_valid_bilaterally(
    signed_successor: str, consumed_successor: str
) -> None:
    hk = _log_signing_keys()
    record = _transfer_record(new_receipt_id=signed_successor, new_holder_kp=NEW_A_HOLDER_KP)
    record["new_receipt_id"] = IteratesAs(consumed_successor, signed_successor)
    evidence = _transfer_log_bundle([record], hk)[0]
    args = AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(consumed_successor, NEW_A_HOLDER_KP)],
        transfer_view=[_claim(record, evidence)],
        revocation_view=[_transferred_revocation()],
        key_manifest=_key_manifest(),
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_anchor_policy(),
    )

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, ERR_ISSUER_SIGNATURE_INVALID)


@pytest.mark.parametrize("rail", ["transfer", "revocation"])
@pytest.mark.parametrize("container", ["none", "dict", "hostile_dict", "generator"])
def test_audit_chain_non_list_container_returns_degraded_never_raises_or_hangs(
    rail: RailName, container: ContainerCase
) -> None:
    args = _valid_args()
    good_claim = cast(list[dict[str, Any]], args.transfer_view)[0]
    good_revocation = cast(list[dict[str, Any]], args.revocation_view)[0]
    if rail == "transfer":
        args.transfer_view = _bad_top_container(container, good_claim)
        expected_error = ERR_NO_TRANSFER_RECORD
    else:
        args.revocation_view = _bad_top_container(container, good_revocation)
        expected_error = ERR_MISSING_BACKED_REVOCATION

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, expected_error)


def _run_infinite_case_in_child(case: InfiniteCase, outbox: Any) -> None:
    try:
        args = _valid_args()
        if case == "infinite_transfer":
            args.transfer_view = NeverEndingTransferView()
            expected_error = ERR_NO_TRANSFER_RECORD
        else:
            args.revocation_view = NeverEndingRevocationView()
            expected_error = ERR_MISSING_BACKED_REVOCATION
        result = _run_audit(args, max_seconds=SUBPROCESS_WALL_SECONDS)
        outbox.put(("returned", result.valid, result.link_status, result.errors, expected_error))
    except BaseException as exc:  # pragma: no cover - reported to the parent.
        outbox.put(("raised", type(exc).__name__, str(exc)))


@pytest.mark.parametrize(
    "case",
    ["infinite_transfer", "infinite_revocation"],
    ids=["transfer_view_infinite_iteration", "revocation_view_infinite_iteration"],
)
def test_audit_chain_list_subclass_infinite_iteration_returns_within_wall_time(
    case: InfiniteCase,
) -> None:
    ctx = multiprocessing.get_context("spawn")
    outbox = ctx.Queue()
    process = ctx.Process(target=_run_infinite_case_in_child, args=(case, outbox))
    started = time.perf_counter()
    process.start()
    process.join(SUBPROCESS_WALL_SECONDS)
    elapsed = time.perf_counter() - started
    if process.is_alive():
        process.terminate()
        process.join()
        pytest.fail(
            f"audit_chain did not return for {case} within "
            f"{SUBPROCESS_WALL_SECONDS:.3f}s wall-clock"
        )
    assert elapsed <= SUBPROCESS_WALL_SECONDS + 0.750
    assert process.exitcode == 0
    try:
        outcome = outbox.get(timeout=0.5)
    except queue.Empty as exc:
        raise AssertionError(f"audit_chain subprocess returned no outcome for {case}") from exc

    assert outcome[0] == "returned", outcome
    _, valid, link_status, errors, expected_error = outcome
    assert valid is False
    assert link_status == ("invalid",)
    assert expected_error in errors, f"expected {expected_error!r} in {errors!r}"


def test_audit_chain_transfer_view_second_pass_fresh_objects_cannot_restrict_good_link() -> None:
    hk = _log_signing_keys()
    selected_record = _transfer_record(OLD_ID, NEW_A_ID, NEW_A_HOLDER_KP, OLD_HOLDER_KP, AT2)
    competing_record = _transfer_record(OLD_ID, NEW_B_ID, NEW_B_HOLDER_KP, OLD_HOLDER_KP, AT)
    competing_evidence, selected_evidence = _transfer_log_bundle(
        [competing_record, selected_record], hk
    )
    args = AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(NEW_A_ID, NEW_A_HOLDER_KP)],
        transfer_view=SecondPassFreshTransferView(
            _claim(selected_record, selected_evidence),
            _claim(competing_record, competing_evidence),
        ),
        revocation_view=[_transferred_revocation(OLD_ID, AT2)],
        key_manifest=_key_manifest(),
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_anchor_policy(),
    )

    result = _run_audit(args)

    _assert_valid_single_link(result)


def test_audit_chain_revocation_list_subclass_iteration_cannot_fabricate_backing() -> None:
    args = _valid_args()
    args.revocation_view = FreshRevocationIterationView(_transferred_revocation())

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, ERR_MISSING_BACKED_REVOCATION)


def test_audit_chain_inadmissible_transfer_claim_set_aside_and_genuine_sibling_honoured() -> None:
    hk = _log_signing_keys()
    good_record = _transfer_record(OLD_ID, NEW_A_ID, NEW_A_HOLDER_KP, OLD_HOLDER_KP, AT)
    bad_record = _transfer_record(OLD_ID, NEW_B_ID, NEW_B_HOLDER_KP, OLD_HOLDER_KP, AT)
    good_evidence, bad_evidence = _transfer_log_bundle([good_record, bad_record], hk)
    bad_claim = _claim(copy.deepcopy(bad_record), bad_evidence)
    del cast(dict[str, Any], bad_claim["record"])["signature"]
    shared_transfer_view = [bad_claim, _claim(good_record, good_evidence)]
    common = AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(NEW_A_ID, NEW_A_HOLDER_KP)],
        transfer_view=shared_transfer_view,
        revocation_view=[_transferred_revocation()],
        key_manifest=_key_manifest(),
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_anchor_policy(),
    )

    good_result = _run_audit(common)
    bad_probe = AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(NEW_B_ID, NEW_B_HOLDER_KP)],
        transfer_view=shared_transfer_view,
        revocation_view=[_transferred_revocation()],
        key_manifest=common.key_manifest,
        log_keys=common.log_keys,
        anchor_policy=common.anchor_policy,
    )
    bad_result = _run_audit(bad_probe)

    _assert_valid_single_link(good_result)
    _assert_invalid_single_link(bad_result)
    _assert_error_present(bad_result, ERR_ISSUER_SIGNATURE_INVALID)


def test_audit_chain_inadmissible_revocation_record_set_aside_and_genuine_sibling_honoured() -> (
    None
):
    args = _valid_args()
    bad_revocation = _transferred_revocation()
    bad_revocation["signature"] = "not a signature block"
    args.revocation_view = [bad_revocation, _transferred_revocation()]

    good_result = _run_audit(args)
    args.revocation_view = [bad_revocation]
    bad_result = _run_audit(args)

    _assert_valid_single_link(good_result)
    _assert_invalid_single_link(bad_result)
    _assert_error_present(bad_result, ERR_MISSING_BACKED_REVOCATION)


def test_audit_chain_honours_genuine_record_with_hostile_mapping_accessor_not_restrictive() -> None:
    hk = _log_signing_keys()
    plain_record = _transfer_record()
    evidence = _transfer_log_bundle([plain_record], hk)[0]
    args = AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(NEW_A_ID, NEW_A_HOLDER_KP)],
        transfer_view=[_claim(HostileGetDict(plain_record), evidence)],
        revocation_view=[HostileGetDict(_transferred_revocation())],
        key_manifest=_key_manifest(),
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_anchor_policy(),
    )

    result = _run_audit(args)

    _assert_valid_single_link(result)


def _apply_malformed_case(args: AuditArgs, case: MalformedCase) -> str:
    claim = cast(list[dict[str, Any]], args.transfer_view)[0]
    record = cast(dict[str, Any], claim["record"])
    revocation_record = cast(list[dict[str, Any]], args.revocation_view)[0]

    if case == "previous_receipt_id_wrong_type":
        args.payloads[0]["receipt_id"] = 2**60
        return ERR_NO_TRANSFER_RECORD
    if case == "previous_buyer_wrong_type":
        args.payloads[0]["buyer"] = "not a buyer object"
        return ERR_HOLDER_AUTHORIZATION_INVALID
    if case == "previous_not_transferable_before_wrong_type":
        args.payloads[0]["license"] = {"not_transferable_before": 2**60}
        return ERR_NOT_TRANSFERABLE_BEFORE
    if case == "next_receipt_id_missing":
        del args.payloads[1]["receipt_id"]
        return ERR_NO_TRANSFER_RECORD
    if case == "next_buyer_pubkey_wrong_type":
        args.payloads[1]["buyer"] = {"pubkey": 2**60}
        return ERR_LOOP_CLOSURE
    if case == "claim_record_missing":
        args.transfer_view = [{"evidence": claim["evidence"]}]
        return ERR_NO_TRANSFER_RECORD
    if case == "claim_record_wrong_type":
        args.transfer_view = [{"record": "not a record", "evidence": claim["evidence"]}]
        return ERR_NO_TRANSFER_RECORD
    if case == "claim_evidence_wrong_type":
        claim["evidence"] = "not an evidence bundle"
        return ERR_TRANSFER_RECORD_NOT_LOGGED
    if case == "evidence_leaf_index_out_of_range":
        evidence = cast(dict[str, Any], claim["evidence"])
        evidence["leaf_index"] = 2**60
        # The unit of admission on this rail is the CLAIM, exactly as in
        # `verify._resolve_transfer_backing`: an integer outside the I-JSON safe
        # range makes the claim unrepresentable, so it is set aside whole and
        # the link has no transfer record at all. The property under test is
        # unchanged -- the link is invalid, never falsely valid -- and only the
        # diagnostic differs from the pre-admission surface, which reported the
        # record as present but unlogged.
        return ERR_NO_TRANSFER_RECORD
    if case == "transfer_record_receipt_id_wrong_type":
        record["receipt_id"] = 2**60
        return ERR_NO_TRANSFER_RECORD
    if case == "transfer_record_new_receipt_id_missing":
        del record["new_receipt_id"]
        return ERR_NO_TRANSFER_RECORD
    if case == "transfer_record_new_holder_pubkey_missing":
        del record["new_holder_pubkey"]
        return ERR_ISSUER_SIGNATURE_INVALID
    if case == "transfer_record_transferred_at_out_of_range":
        record["transferred_at"] = 2**60
        # Same rule, same reason as `evidence_leaf_index_out_of_range` above:
        # the claim carrying the out-of-range integer is not representable, so
        # it is set aside whole rather than reported as a record whose issuer
        # signature does not verify.
        return ERR_NO_TRANSFER_RECORD
    if case == "transfer_record_signature_missing":
        del record["signature"]
        return ERR_ISSUER_SIGNATURE_INVALID
    if case == "revocation_record_receipt_id_wrong_type":
        revocation_record["receipt_id"] = 2**60
        return ERR_MISSING_BACKED_REVOCATION
    if case == "revocation_record_status_missing":
        del revocation_record["status"]
        return ERR_MISSING_BACKED_REVOCATION
    if case == "revocation_record_revoked_at_out_of_range":
        revocation_record["revoked_at"] = 2**60
        return ERR_MISSING_BACKED_REVOCATION
    if case == "revocation_record_signature_wrong_type":
        revocation_record["signature"] = "not a signature block"
        return ERR_MISSING_BACKED_REVOCATION
    raise AssertionError(f"unhandled malformed case {case!r}")


@pytest.mark.parametrize(
    "case",
    [
        "previous_receipt_id_wrong_type",
        "previous_buyer_wrong_type",
        "previous_not_transferable_before_wrong_type",
        "next_receipt_id_missing",
        "next_buyer_pubkey_wrong_type",
        "claim_record_missing",
        "claim_record_wrong_type",
        "claim_evidence_wrong_type",
        "evidence_leaf_index_out_of_range",
        "transfer_record_receipt_id_wrong_type",
        "transfer_record_new_receipt_id_missing",
        "transfer_record_new_holder_pubkey_missing",
        "transfer_record_transferred_at_out_of_range",
        "transfer_record_signature_missing",
        "revocation_record_receipt_id_wrong_type",
        "revocation_record_status_missing",
        "revocation_record_revoked_at_out_of_range",
        "revocation_record_signature_wrong_type",
    ],
)
def test_audit_chain_malformed_inputs_return_invalid_never_permissive_false_valid(
    case: MalformedCase,
) -> None:
    args = _valid_args()
    expected_error = _apply_malformed_case(args, case)

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, expected_error)


def test_audit_chain_duplicate_claims_same_predecessor_use_earliest_log_index_not_view_order() -> (
    None
):
    hk = _log_signing_keys()
    early_record = _transfer_record(OLD_ID, NEW_B_ID, NEW_B_HOLDER_KP, OLD_HOLDER_KP, AT)
    losing_record = _transfer_record(OLD_ID, NEW_A_ID, NEW_A_HOLDER_KP, OLD_HOLDER_KP, AT)
    early_evidence, losing_evidence = _transfer_log_bundle([early_record, losing_record], hk)
    args = AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(NEW_A_ID, NEW_A_HOLDER_KP)],
        transfer_view=[
            _claim(losing_record, losing_evidence),
            _claim(early_record, early_evidence),
        ],
        revocation_view=[_transferred_revocation()],
        key_manifest=_key_manifest(),
        log_keys=[_transfer_log_key(hk)],
        anchor_policy=_anchor_policy(),
    )

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, ERR_LOSING_BRANCH)


def test_audit_chain_oversized_transfer_claim_count_never_buys_permissive_valid_link() -> None:
    args = _valid_args()
    good_claim = cast(list[dict[str, Any]], args.transfer_view)[0]
    args.transfer_view = [{"record": "not a record", "evidence": None} for _ in range(64)] + [
        good_claim
    ]

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, ERR_NO_TRANSFER_RECORD)


def test_audit_chain_oversized_revocation_record_count_never_buys_permissive_valid_link() -> None:
    args = _valid_args()
    args.revocation_view = [
        {"receipt_id": NEW_C_ID, "status": "transferred", "revoked_at": AT} for _ in range(10_000)
    ] + [_transferred_revocation()]

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, ERR_MISSING_BACKED_REVOCATION)


def test_audit_chain_duplicate_unlogged_records_stay_invalid_never_permissive() -> None:
    record = _transfer_record()
    args = AuditArgs(
        payloads=[_payload(OLD_ID, OLD_HOLDER_KP), _payload(NEW_A_ID, NEW_A_HOLDER_KP)],
        transfer_view=[_claim(copy.deepcopy(record), None), _claim(copy.deepcopy(record), None)],
        revocation_view=[_transferred_revocation()],
        key_manifest=_key_manifest(),
        log_keys=[_transfer_log_key(_log_signing_keys())],
        anchor_policy=_anchor_policy(),
    )

    result = _run_audit(args)

    _assert_invalid_single_link(result)
    _assert_error_present(result, ERR_TRANSFER_RECORD_NOT_LOGGED)
