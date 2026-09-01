"""IssuingCore: turns a `NormalizedPurchase` into a signed v0.2 attest receipt.

Reuse 1:1 (Global Constraint 3): payload assembly is `issue.build_payload(...)`,
signing is `issue.issue(...)` — the bridge NEVER constructs `buyer`/`license`/
`signatures` by hand and never touches `canon`/`keys`/`pq` for issuance
itself. The real verifier is the test oracle (`test_bridge_core_oracle.py`):
every envelope this class returns must pass `attest.verify.verify`.

Buyer binding (Global Constraint 6): a fresh 16-byte salt + email commitment
on every receipt (computed by `build_payload`, never by the bridge);
`license.transferable = (buyer_pubkey is not None)` — the §17.8/D1 invariant.
A malformed pubkey fails BEFORE anything is signed — the gate in `issue_for`
step 0 is defense-in-depth: `attest_bridge.model.decode_buyer_pubkey` already
rejects a malformed pubkey at the adapter boundary, but `IssuingCore` never
trusts a caller to have done so.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from attest import issue, manifests
from attest import verify as verifier
from attest_bridge.catalog import ProductCatalog
from attest_bridge.delivery import Delivery
from attest_bridge.ledger import Ledger, ReceiptAlreadyRecorded
from attest_bridge.model import NormalizedPurchase, PurchaseRejected, purchase_id_for_log
from attest_bridge.signing import IssuerIdentity

_ED25519_PUBKEY_LEN = 32
_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
_log = logging.getLogger("attest_bridge.core")


def _now_rfc3339() -> str:
    return datetime.now(UTC).strftime(_RFC3339)


@dataclass(frozen=True, slots=True)
class IssueOutcome:
    receipt_id: str
    envelope: dict[str, Any]
    duplicate: bool  # True: (platform, purchase_id) already had a receipt — returned, not re-issued


class IssuingCore:
    """Platform-agnostic issuance core: `NormalizedPurchase` in, signed v0.2
    attest receipt envelope out. Consumes `attest.issue.build_payload`/
    `attest.issue.issue` 1:1 — see module docstring."""

    def __init__(
        self,
        *,
        catalog: ProductCatalog,
        issuer: IssuerIdentity,
        ledger: Ledger,
        public_base_url: str,
        delivery: Delivery | None = None,
    ) -> None:
        self._catalog = catalog
        self._issuer = issuer
        self._ledger = ledger
        self._public_base_url = public_base_url
        self._delivery = delivery

    @property
    def has_configured_products(self) -> bool:
        """Whether any purchase could resolve to terms at all.

        Asked of the catalog this core will actually resolve against, not of
        the config it was built from: readiness must report on the object
        that decides, or it reports on a copy that can drift from it.
        """
        return bool(self._catalog.keys())

    def signing_key_within_validity(self, *, at: str) -> bool:
        """Whether this issuer's `kid` may sign at RFC3339 instant `at`.

        One definition, two callers: `issue_for` refuses a purchase on it,
        and the readiness route reports on it. Kept as a method rather than
        duplicated at the HTTP layer so the two can never drift into
        disagreeing about whether this bridge can still issue.
        """
        entry = manifests.find_key(self._issuer.manifest_snapshot, self._issuer.kid)
        return entry is not None and verifier._within_validity(at, entry)

    def issue_for(self, purchase: NormalizedPurchase) -> IssueOutcome:
        """Issue (or return the already-issued) receipt for `purchase`.

        Raises `PurchaseRejected` on a malformed buyer pubkey (before any
        signing) and `UnmappedProduct` when `purchase.product_key` has no
        catalog entry (propagated from `ProductCatalog.resolve`, never
        guessed). Any `attest.issue.IssueError` escapes as-is — a bug, not a
        purchase-input problem (500 path, T8).

        Under concurrency the idempotency check at step (1) and the write at
        step (7) are a check-then-act pair, and a second process (a
        `retry-failed` run, another worker) can record the same purchase in
        between. First writer wins: the loser discards what it just signed and
        returns the STORED receipt as a duplicate outcome. The losing
        envelope and its buyer-binding salt are never delivered and never
        recorded, so one purchase keeps exactly one salt.
        """
        # (0) Defense-in-depth re-gate: the adapter boundary already rejects a
        # malformed pubkey (`model.decode_buyer_pubkey`), but this class never
        # trusts that gate alone — nothing may be signed for a bad pubkey.
        if purchase.buyer_pubkey is not None and len(purchase.buyer_pubkey) != _ED25519_PUBKEY_LEN:
            raise PurchaseRejected(
                f"buyer pubkey must be {_ED25519_PUBKEY_LEN} bytes, "
                f"got {len(purchase.buyer_pubkey)}"
            )

        # (1) Idempotency: a (platform, purchase_id) pair that already has a
        # stored receipt is returned verbatim, never re-issued.
        stored = self._ledger.get_receipt(purchase.platform, purchase.platform_purchase_id)
        if stored is not None:
            return IssueOutcome(
                receipt_id=stored.receipt_id,
                envelope=json.loads(stored.envelope_json),
                duplicate=True,
            )

        # (2) Catalog resolution — UnmappedProduct propagates untouched.
        template = self._catalog.resolve(purchase.product_key)

        # (3) A daemon can outlive its signing key. Refuse this purchase in the
        # recoverable path rather than producing a receipt the verifier rejects.
        issued_at = _now_rfc3339()
        if not self.signing_key_within_validity(at=issued_at):
            reason = f"signing key {self._issuer.kid!r} is outside its validity window"
            _log.error(
                "purchase %s rejected: %s",
                purchase_id_for_log(purchase.platform_purchase_id),
                reason,
            )
            raise PurchaseRejected(reason)

        # (4) Fresh, unique salt for this receipt's buyer-binding commitment.
        salt = secrets.token_bytes(16)

        # (5) Assemble the payload — 1:1 via `issue.build_payload`, never
        # hand-built.
        payload = issue.build_payload(
            attest_version="0.2",
            issuer_id=self._issuer.issuer_id,
            display_name=self._issuer.display_name,
            buyer_identifier=purchase.buyer_identifier,
            buyer_identifier_type=purchase.identifier_type,
            buyer_salt=salt,
            buyer_pubkey=purchase.buyer_pubkey,
            transferable=purchase.buyer_pubkey is not None,
            title=template.title,
            publisher=template.publisher,
            identifiers=dict(template.identifiers),
            artifact_series=template.artifact_series,
            terms_uri=template.terms_uri,
            legal_text_sha256=template.legal_text_sha256,
            grant=template.grant,
            revocability=template.revocability,
            revocation_window_days=template.revocation_window_days,
            drm=template.drm,
            edition=template.edition,
            issued_at=issued_at,
        )

        # (6) Sign — 1:1 via `issue.issue`, never hand-signed.
        envelope = issue.issue(
            payload,
            self._issuer.signing_keys,
            self._issuer.kid,
            salt=salt,
            manifest_snapshot=self._issuer.manifest_snapshot,
        )

        # (7) Record in the Ledger before returning (Global Constraint 9:
        # issue + ledger-record first, delivery — T6 — happens after).
        receipt_id: str = payload["receipt_id"]
        try:
            self._ledger.record_receipt(
                platform=purchase.platform,
                purchase_id=purchase.platform_purchase_id,
                receipt_id=receipt_id,
                envelope=envelope,
                buyer_email=purchase.buyer_identifier,
                download_token=secrets.token_urlsafe(32),
                issued_at=payload["issued_at"],
            )
        except ReceiptAlreadyRecorded:
            # Re-read rather than infer. Two constraints can reject this
            # INSERT and only one of them means "already issued": if the
            # purchase's row is there, a rival recorded it between step (1)
            # and here and its receipt is the real one. If it is NOT there,
            # what fired was the UNIQUE download_token — a different purchase
            # entirely — and answering with a duplicate outcome would hand
            # this buyer a receipt that was never issued to them.
            winner = self._ledger.get_receipt(purchase.platform, purchase.platform_purchase_id)
            if winner is None:
                raise
            _log.warning(
                "purchase %s was recorded by another writer first: returning the stored receipt",
                purchase_id_for_log(purchase.platform_purchase_id),
            )
            return IssueOutcome(
                receipt_id=winner.receipt_id,
                envelope=json.loads(winner.envelope_json),
                duplicate=True,
            )

        return IssueOutcome(receipt_id=receipt_id, envelope=envelope, duplicate=False)

    def process(self, purchase: NormalizedPurchase) -> IssueOutcome:
        """Issue (or return the already-issued) receipt, then attempt delivery.

        Global Constraint 9: issue + ledger-record happen first — inside
        `issue_for`, which returns before this method ever touches delivery —
        so the receipt is durably safe in the Ledger before any delivery is
        attempted. An SMTP failure is recorded (`record_delivery_failure`)
        and the receipt stays downloadable via its token link; it is never
        lost. Delivery is at-least-once: a crash after SMTP acceptance and
        before `mark_delivered` can resend this exact stored envelope during a
        sweep; it is never re-issued. A receipt already marked delivered is
        never resent.
        """
        outcome = self.issue_for(purchase)

        stored = self._ledger.get_receipt(purchase.platform, purchase.platform_purchase_id)
        if stored is None:
            # issue_for() just inserted this row (fresh receipt) or found it
            # already there (duplicate) — a missing row here means Ledger
            # state was corrupted between the two calls, not a purchase-input
            # problem worth reporting to the caller as such.
            raise RuntimeError(
                f"receipt for platform={purchase.platform!r} "
                f"purchase_id={purchase_id_for_log(purchase.platform_purchase_id)} "
                "vanished immediately "
                "after issue_for"
            )

        if stored.delivered_at is not None:
            return outcome

        if self._delivery is None:
            # No Delivery wired into this core at all: zero-config mode at
            # the core level — the download link IS the delivery, nothing to
            # attempt or record.
            return outcome

        download_url = f"{self._public_base_url}/r/{stored.download_token}"
        result = self._delivery.send(
            to_email=stored.buyer_email,
            receipt_id=stored.receipt_id,
            work_title=outcome.envelope["payload"]["work"]["title"],
            envelope=outcome.envelope,
            download_url=download_url,
            info_url=None,
        )
        if result.status == "sent":
            self._ledger.mark_delivered(
                purchase.platform, purchase.platform_purchase_id, at=_now_rfc3339()
            )
        elif result.status == "failed":
            self._ledger.record_delivery_failure(
                purchase.platform,
                purchase.platform_purchase_id,
                result.detail if result.detail is not None else "delivery failed",
            )
        # "skipped_no_smtp": leave the receipt as-is — download-link-only mode.

        return outcome
