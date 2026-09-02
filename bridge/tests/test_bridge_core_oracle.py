"""THE oracle: every receipt the bridge emits must satisfy the real verifier."""

from __future__ import annotations

import json
import smtplib
from pathlib import Path
from typing import Any

import pytest
from attest_bridge.config import DeliveryConfig, IssuerConfig
from attest_bridge.core import IssuingCore
from attest_bridge.delivery import Delivery
from attest_bridge.model import NormalizedPurchase, PurchaseRejected, UnmappedProduct
from attest_bridge.signing import load_issuer
from conftest import ISSUER, KID

from attest import anchor, bundle, cli, keys, pq, revocation, tlog, transfer
from attest import verify as verify_mod


def _purchase(**overrides: Any) -> NormalizedPurchase:
    base: dict[str, Any] = dict(
        platform="stripe",
        platform_purchase_id="cs_test_0001",
        buyer_identifier="buyer@example.com",
        identifier_type="email",
        buyer_pubkey=None,
        product_key="price_TEST",
        purchased_at="2026-07-24T10:00:00Z",
        amount="1999",
        currency="eur",
    )
    base.update(overrides)
    return NormalizedPurchase(**base)


def _envelope_bytes(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def test_email_bound_receipt_verifies_offline_ok(core: IssuingCore, trust_store: Any) -> None:
    outcome = core.issue_for(_purchase())
    result = verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store)
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.ok is True
    payload = outcome.envelope["payload"]
    assert payload["attest_version"] == "0.2"
    assert payload["license"]["transferable"] is False
    assert payload["buyer"]["pubkey"] is None


def test_issue_for_rejects_when_the_daemon_key_has_expired(
    core: IssuingCore,
    ledger: Any,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr("attest_bridge.core._now_rfc3339", lambda: "2100-01-01T00:00:00Z")
    monkeypatch.setattr("attest_bridge.core.verifier._within_validity", lambda *_: False)

    with pytest.raises(PurchaseRejected, match="validity window"):
        core.issue_for(_purchase(platform_purchase_id="cs_expired_key"))
    assert ledger.get_receipt("stripe", "cs_expired_key") is None
    assert "cs_expired_key" not in caplog.text
    assert "sha256:a0f1ed324955" in caplog.text


def test_real_loader_identity_issues_a_receipt_the_oracle_accepts(
    tmp_path: Path, catalog: Any, ledger: Any, hybrid_keys: Any, key_manifest: Any, trust_store: Any
) -> None:
    seed_path = tmp_path / "issuer.seed"
    seed_path.write_text(keys.b64u(hybrid_keys.ed.seed), encoding="utf-8")
    mldsa_path = tmp_path / "issuer.mldsa.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(key_manifest), encoding="utf-8")
    issuer = load_issuer(
        IssuerConfig(
            ISSUER,
            "Example Games Store",
            next(iter(key_manifest["keys"]))["kid"],
            seed_path,
            mldsa_path,
            manifest_path,
        )
    )
    outcome = IssuingCore(
        catalog=catalog,
        issuer=issuer,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
    ).issue_for(_purchase(platform_purchase_id="cs_loaded_oracle"))

    assert verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store).ok is True


def test_embedded_salt_proves_binding_via_real_verifier(
    core: IssuingCore, trust_store: Any
) -> None:
    outcome = core.issue_for(_purchase(platform_purchase_id="cs_test_0002"))
    salt = keys.b64u_decode(outcome.envelope["delivery"]["salt"])
    assert len(salt) == 16
    disclosure = verify_mod.Disclosure(
        identifier="buyer@example.com", identifier_type="email", salt=salt
    )
    result = verify_mod.verify(
        _envelope_bytes(outcome.envelope), trust_store, disclosure=disclosure
    )
    assert result.binding == "proven"
    # wrong email must NOT prove — the commitment is real, not decorative
    wrong = verify_mod.Disclosure(
        identifier="other@example.com", identifier_type="email", salt=salt
    )
    assert (
        verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store, disclosure=wrong).binding
        == "not_proven"
    )


def test_pubkey_bound_receipt_is_transferable_and_passes_chain_audit(
    core: IssuingCore, trust_store: Any, key_manifest: dict[str, Any]
) -> None:
    buyer_kp = keys.generate()
    outcome = core.issue_for(
        _purchase(platform_purchase_id="cs_test_0003", buyer_pubkey=buyer_kp.pub)
    )
    payload = outcome.envelope["payload"]
    assert payload["license"]["transferable"] is True  # §17.8/D1 invariant
    assert payload["buyer"]["pubkey"] == keys.b64u(buyer_kp.pub)
    assert verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store).ok is True
    audit = transfer.audit_chain(
        [payload],
        [],
        [],
        key_manifest,
        [],
        anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )
    assert audit.valid is True
    assert audit.link_status == ()


def test_email_bound_receipt_has_trivially_valid_chain_audit_at_zero_links(
    core: IssuingCore, trust_store: Any, key_manifest: dict[str, Any]
) -> None:
    # The bridge only ever EMITS receipts, never TRANSFERS them — that is the
    # normal case (no buyer_pubkey, license.transferable is False). A fresh
    # email-bound receipt therefore has no transfer chain at all, and
    # audit_chain's answer for it is trivial: valid with zero links, not a
    # check that got skipped. This is the sibling of
    # test_pubkey_bound_receipt_is_transferable_and_passes_chain_audit above,
    # which exercises the transferable branch.
    outcome = core.issue_for(_purchase(platform_purchase_id="cs_test_0003b"))
    payload = outcome.envelope["payload"]
    assert payload["license"]["transferable"] is False
    assert verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store).ok is True
    audit = transfer.audit_chain(
        [payload],
        [],
        [],
        key_manifest,
        [],
        anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )
    assert audit.valid is True
    assert audit.link_status == ()


def test_bridge_receipt_passes_attest_verify_cli(
    core: IssuingCore, key_manifest: dict[str, Any], tmp_path: Any, capsys: Any
) -> None:
    outcome = core.issue_for(_purchase(platform_purchase_id="cs_test_0004"))
    receipt = tmp_path / "receipt.attest"
    receipt.write_text(json.dumps(outcome.envelope), encoding="utf-8")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "manifest.json").write_text(json.dumps(key_manifest), encoding="utf-8")
    rc = cli.main(["verify", str(receipt), "--trust-dir", str(trust_dir)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["ok"] is True


def test_salt_is_fresh_per_receipt(core: IssuingCore) -> None:
    a = core.issue_for(_purchase(platform_purchase_id="cs_a"))
    b = core.issue_for(_purchase(platform_purchase_id="cs_b"))
    assert a.envelope["delivery"]["salt"] != b.envelope["delivery"]["salt"]


def test_duplicate_purchase_returns_stored_receipt_never_reissues(
    core: IssuingCore, ledger: Any
) -> None:
    first = core.issue_for(_purchase(platform_purchase_id="cs_dup"))
    second = core.issue_for(_purchase(platform_purchase_id="cs_dup"))
    assert second.duplicate is True
    assert second.receipt_id == first.receipt_id
    assert second.envelope == first.envelope


def test_unmapped_product_never_issues(core: IssuingCore, ledger: Any) -> None:
    with pytest.raises(UnmappedProduct):
        core.issue_for(_purchase(platform_purchase_id="cs_um", product_key="price_UNKNOWN"))
    assert ledger.get_receipt("stripe", "cs_um") is None


def test_malformed_pubkey_fails_before_signing(core: IssuingCore, ledger: Any) -> None:
    # 31 bytes: survives the DTO only if an adapter mis-decodes; core must still refuse.
    with pytest.raises(PurchaseRejected):
        core.issue_for(_purchase(platform_purchase_id="cs_bad", buyer_pubkey=b"\x01" * 31))
    assert ledger.get_receipt("stripe", "cs_bad") is None


def test_issuer_manifest_is_embedded_for_offline_verification(
    core: IssuingCore, key_manifest: dict[str, Any]
) -> None:
    outcome = core.issue_for(_purchase(platform_purchase_id="cs_manifest"))
    assert outcome.envelope["delivery"]["issuer_manifest"] == key_manifest
    assert outcome.envelope["payload"]["issuer"]["id"] == ISSUER


# -- process(): delivery wiring (Global Constraint 9 — issue+record first) --


def _delivery_config() -> DeliveryConfig:
    return DeliveryConfig(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="merchant",
        smtp_password="hunter2-super-secret",  # noqa: S106 - test fixture, not a real secret
        from_address="receipts@merchant.example.com",
        info_url="https://merchant.example.com/attest/what-is-this",
    )


class _FailingSMTP:
    """Fails at login, every time — no real network, never reaches send_message."""

    def __init__(self, host: str, port: int) -> None:
        pass

    def starttls(self, *, context: Any) -> None:
        pass

    def login(self, username: str, password: str) -> None:
        raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    def send_message(self, message: Any) -> None:  # pragma: no cover
        raise AssertionError("send_message must not be reached after login fails")

    def quit(self) -> None:
        pass

    def __enter__(self) -> _FailingSMTP:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


def _make_succeeding_smtp_factory() -> tuple[Any, list[int]]:
    """Returns (factory, calls) — `calls` grows by one per `send_message`."""
    calls: list[int] = []

    class _SucceedingSMTP:
        def __init__(self, host: str, port: int) -> None:
            pass

        def starttls(self, *, context: Any) -> None:
            pass

        def login(self, username: str, password: str) -> None:
            pass

        def send_message(self, message: Any) -> None:
            calls.append(1)

        def quit(self) -> None:
            pass

        def __enter__(self) -> _SucceedingSMTP:
            return self

        def __exit__(self, *exc_info: object) -> None:
            pass

    return _SucceedingSMTP, calls


def test_process_smtp_failure_keeps_receipt_safe_in_ledger_and_it_still_verifies(
    catalog: Any, issuer_identity: Any, ledger: Any, trust_store: Any, legal_texts: dict[str, bytes]
) -> None:
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(_delivery_config(), smtp_factory=_FailingSMTP, legal_texts=legal_texts),
    )
    outcome = core.process(_purchase(platform_purchase_id="cs_delivery_fail"))

    # Global Constraint 9: a delivery failure never loses a receipt — it is
    # already durably recorded, retriable, and still a fully valid envelope.
    stored = ledger.get_receipt("stripe", "cs_delivery_fail")
    assert stored is not None
    assert stored.delivered_at is None
    assert stored.delivery_attempts == 1
    assert stored.last_delivery_error is not None
    assert "hunter2-super-secret" not in stored.last_delivery_error

    result = verify_mod.verify(_envelope_bytes(outcome.envelope), trust_store)
    assert result.ok is True


def test_process_does_not_resend_to_an_already_delivered_receipt(
    catalog: Any, issuer_identity: Any, ledger: Any, legal_texts: dict[str, bytes]
) -> None:
    factory, calls = _make_succeeding_smtp_factory()
    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(_delivery_config(), smtp_factory=factory, legal_texts=legal_texts),
    )
    purchase = _purchase(platform_purchase_id="cs_no_resend")

    first = core.process(purchase)
    second = core.process(purchase)

    assert len(calls) == 1  # the fake's send_message was invoked exactly once
    assert second.duplicate is True
    assert second.receipt_id == first.receipt_id

    stored = ledger.get_receipt("stripe", "cs_no_resend")
    assert stored is not None
    assert stored.delivered_at is not None
    assert stored.delivery_attempts == 0


def test_delivered_email_carries_an_importable_bundle_that_verifies_offline(
    catalog: Any,
    issuer_identity: Any,
    ledger: Any,
    legal_texts: dict[str, bytes],
    tmp_path: Path,
) -> None:
    """The buyer's own path, end to end, on a real signed sale.

    Not a shape assertion on a hand-built fake: a real receipt is issued and
    delivered, both attachments are written to disk exactly as a mail client
    would save them, and the pair is re-imported and verified against the
    trust store the BUNDLE carries — the store the buyer would still have if
    the merchant vanished the next day.
    """
    captured: list[Any] = []

    class _CapturingSMTP:
        def __init__(self, host: str, port: int) -> None:
            pass

        def starttls(self, *, context: Any) -> None:
            pass

        def login(self, username: str, password: str) -> None:
            pass

        def send_message(self, message: Any) -> None:
            captured.append(message)

        def quit(self) -> None:
            pass

        def __enter__(self) -> _CapturingSMTP:
            return self

        def __exit__(self, *exc_info: object) -> None:
            pass

    core = IssuingCore(
        catalog=catalog,
        issuer=issuer_identity,
        ledger=ledger,
        public_base_url="https://receipts.example.com",
        delivery=Delivery(_delivery_config(), smtp_factory=_CapturingSMTP, legal_texts=legal_texts),
    )
    outcome = core.process(_purchase(platform_purchase_id="cs_bundle_e2e"))

    attachments = list(captured[0].iter_attachments())
    assert len(attachments) == 2
    paths: list[Path] = []
    for attachment in attachments:
        filename = attachment.get_filename()
        assert filename is not None
        content = attachment.get_content()
        path = tmp_path / filename
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else bytes(content))
        paths.append(path)
    attest_path, private_path = paths
    assert attest_path.name.endswith(".attest")
    assert private_path.name.endswith(".private.attest")

    imported = bundle.import_bundle(attest_path, private_path)

    assert len(imported.receipts) == 1
    extracted = imported.receipts[0]
    assert extracted["payload"]["receipt_id"] == outcome.receipt_id
    result = verify_mod.verify(_envelope_bytes(extracted), imported.trust_store)
    assert result.ok is True
    assert imported.salts[outcome.receipt_id] == keys.b64u_decode(
        outcome.envelope["delivery"]["salt"]
    )
    assert (
        imported.legal_texts[extracted["payload"]["license"]["legal_text_sha256"]]
        == (legal_texts[extracted["payload"]["license"]["legal_text_sha256"]])
    )


# -- chain of title: the bridge's receipt as a real root ------------------------
#
# The two zero-link audits above cannot fail. `audit_chain` over a freshly
# issued receipt returns valid with no links for ANY input, so they certify
# nothing about what the bridge actually bound into the receipt — a bridge
# that wrote the wrong pubkey, or none, would keep them green. The tests below
# build the FIRST REAL LINK on top of a bridge receipt, which is the only way
# to ask the audit surface a question about this bridge's work.

_TRANSFER_LOG_ORIGIN = "transfer-log.example.com/2026"
_TRANSFER_LOG_NAME = "attest-transfer-log-1"
_NEW_RECEIPT_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
_TRANSFERRED_AT = "2026-08-01T00:00:00Z"


@pytest.fixture(scope="session")
def transfer_log_keys() -> pq.HybridSigningKeys:
    """The transfer log is a third party: its own keys, not the issuer's."""
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _logged(record: dict[str, Any], log_keys: pq.HybridSigningKeys) -> dict[str, Any]:
    """One genuine transfer-log inclusion bundle for a single record."""
    entry = {
        "type": "transfer-record",
        "issuer": ISSUER,
        "record_sha256": transfer.record_hash(record),
    }
    leaves = [tlog.encode_entry(entry)]
    checkpoint = tlog.sign_checkpoint(
        _TRANSFER_LOG_ORIGIN, len(leaves), tlog.build_tree(leaves), log_keys, _TRANSFER_LOG_NAME
    )
    return {
        "entry": entry,
        "leaf_index": 0,
        "tree_size": len(leaves),
        "inclusion_proof": [node.hex() for node in tlog.inclusion_proof(leaves, 0)],
        "checkpoint": checkpoint,
    }


def _audit_one_transfer(
    *,
    core: IssuingCore,
    key_manifest: dict[str, Any],
    hybrid_keys: pq.HybridSigningKeys,
    log_keys: pq.HybridSigningKeys,
    purchase_id: str,
    buyer_kp: keys.SigningKeyPair,
    authorizing_kp: keys.SigningKeyPair,
) -> transfer.ChainAuditResult:
    """Issue through the bridge, then audit one transfer away from it.

    `authorizing_kp` is what the two callers vary: the buyer's own key, which
    the receipt names as the holder, or a stranger's.
    """
    outcome = core.issue_for(_purchase(platform_purchase_id=purchase_id, buyer_pubkey=buyer_kp.pub))
    payload = outcome.envelope["payload"]
    new_holder = keys.generate()
    new_holder_pubkey = keys.b64u(new_holder.pub)

    record = transfer.build_record(
        payload["receipt_id"],
        _NEW_RECEIPT_ID,
        new_holder_pubkey,
        _TRANSFERRED_AT,
        transfer.sign_authorization(
            payload["receipt_id"], new_holder_pubkey, _TRANSFERRED_AT, authorizing_kp
        ),
        hybrid_keys,
        KID,
    )
    return transfer.audit_chain(
        [payload, {"receipt_id": _NEW_RECEIPT_ID, "buyer": {"pubkey": new_holder_pubkey}}],
        [{"record": record, "evidence": _logged(record, log_keys)}],
        [
            revocation.build_record(
                payload["receipt_id"], "transferred", _TRANSFERRED_AT, hybrid_keys, KID
            )
        ],
        key_manifest,
        [
            tlog.LogKey(
                origin=_TRANSFER_LOG_ORIGIN,
                name=_TRANSFER_LOG_NAME,
                ed25519_pub=log_keys.ed.pub,
                mldsa_pub=log_keys.mldsa.pub,
            )
        ],
        anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None),
    )


def test_a_bridge_receipt_is_a_working_root_of_title(
    core: IssuingCore,
    key_manifest: dict[str, Any],
    hybrid_keys: pq.HybridSigningKeys,
    transfer_log_keys: pq.HybridSigningKeys,
) -> None:
    """The buyer's own key can move a bridge-issued receipt on.

    This is the claim the bridge makes to a buyer who supplies a pubkey, and
    until there is a link in the chain nothing checks it: the audit has to
    accept a transfer authorized by exactly the key the bridge committed to.
    """
    buyer_kp = keys.generate()

    audit = _audit_one_transfer(
        core=core,
        key_manifest=key_manifest,
        hybrid_keys=hybrid_keys,
        log_keys=transfer_log_keys,
        purchase_id="cs_test_chain_ok",
        buyer_kp=buyer_kp,
        authorizing_kp=buyer_kp,
    )

    assert audit.valid is True, audit.errors
    assert audit.link_status == ("valid",)


def test_a_transfer_the_buyer_never_authorized_does_not_audit(
    core: IssuingCore,
    key_manifest: dict[str, Any],
    hybrid_keys: pq.HybridSigningKeys,
    transfer_log_keys: pq.HybridSigningKeys,
) -> None:
    """The same chain, signed by someone who is not the holder.

    Without this the positive test above proves only that `audit_chain`
    returns valid — the answer it also gives when it is not looking. Here
    everything is genuine except the one signature that matters: the record
    is issuer-signed, logged and revoked exactly as before.
    """
    audit = _audit_one_transfer(
        core=core,
        key_manifest=key_manifest,
        hybrid_keys=hybrid_keys,
        log_keys=transfer_log_keys,
        purchase_id="cs_test_chain_forged",
        buyer_kp=keys.generate(),
        authorizing_kp=keys.generate(),
    )

    assert audit.valid is False
    assert audit.link_status == ("invalid",)
