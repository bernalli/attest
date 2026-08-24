"""itch.io adapter: a claim-queue poller, not a webhook (OI-4,
source-verified 2026-07-24 against the live API — see below).

itch.io exposes no purchase webhook and no purchase-enumeration/pagination/
cursor endpoint at all: `api.itch.io` offers only `credentials/info`,
`profile`, `profile/games`, `games/{id}/purchases?email=|user_id=`,
`games/{id}/download_keys?...`, `wharf/latest`. So issuance here can never be
push-driven — it is a claim-queue poller: a buyer (via `POST /itch/claim`,
`http.py`) or a merchant CSV backfill (`itch-import`, `cli.py`) enqueues an
(email, game_id) CLAIM in the Ledger; each `ItchPoller.tick` drains DUE claims
by calling `GET /games/{game_id}/purchases?email=...` and treats THE API
RESPONSE AS THE SOLE ISSUANCE AUTHORITY.

This is the load-bearing invariant of this whole module: a claim or a CSV row
NEVER causes issuance on its own — only an itch-API-confirmed purchase does.
The one line that gates every `core.process` call in `ItchPoller.tick` is
inside the `for raw in purchases` loop, where `purchases` is exactly what
`ItchAdapter.fetch_purchases` returned from the LIVE API call for THIS tick —
there is no other code path in this module, in `http.py`'s `/itch/claim`
routes, or in `cli.py`'s `itch-import` that ever calls `core.process`.
Enqueuing a claim only ever inserts a row in the `claims` table; a CSV row
only ever does the same, once per unique email — neither can, by itself,
produce a receipt.

Dedup is on the purchase `id` against the Ledger's `(platform, purchase_id)`
set (`Ledger.get_receipt`), exactly like Stripe's event/purchase dedup — see
`ItchPoller`'s class docstring for the cross-platform concurrency argument.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from attest_bridge._http import https_get as _default_http_get
from attest_bridge.core import IssuingCore
from attest_bridge.ledger import Claim, Ledger
from attest_bridge.model import (
    BridgeError,
    NormalizedPurchase,
    PurchaseRejected,
    UnmappedProduct,
    purchase_id_for_log,
)

_log = logging.getLogger("attest_bridge.itch")

_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"
# itch.io's documented purchase timestamp form (space-separated, implicitly
# UTC, no offset). The ISO-8601/RFC3339 form (with or without an explicit
# offset, including a trailing "Z") is accepted via `datetime.fromisoformat`
# as a fallback — see `_parse_itch_created_at`.
_ITCH_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
# A purchase in either of these states was reversed after the fact: it must
# never be issued, and — per `ItchPoller.tick` — is treated as though it
# doesn't exist at all for retry purposes (the claim stays pending).
_SKIP_STATUSES = frozenset({"refunded", "canceled"})


class ItchApiError(BridgeError):
    """`api.itch.io` returned a non-200 response, or the body was unparseable."""


def _scrub(text: str, *, email: str, api_key: str) -> str:
    """Remove the buyer's address — plain and percent-encoded — and the API key
    from an API error message, at the point the message is built rather than at
    the point it is logged. The request URL carries the address as a query
    parameter and the key travels in a header, so an exception whose text this
    module does not control could echo either; every consumer downstream then
    gets a message that is already safe to log or store."""
    for secret, placeholder in (
        (email, "<redacted-email>"),
        (quote(email, safe=""), "<redacted-email>"),
        (api_key, "<redacted-api-key>"),
    ):
        if secret:
            text = text.replace(secret, placeholder)
    return text


def _parse_itch_created_at(raw: Any) -> str:
    """Accept itch's documented `"YYYY-MM-DD HH:MM:SS"` form or any ISO-8601
    form (with or without an explicit UTC offset); return RFC3339 `...Z`.

    Anything else is a malformed purchase input — `PurchaseRejected`, never
    signed (mirrors `StripeAdapter.normalize`'s fail-before-signing posture).
    """
    if not isinstance(raw, str) or not raw.strip():
        raise PurchaseRejected(f"itch purchase created_at is not a non-empty string: {raw!r}")
    text = raw.strip()
    try:
        parsed = datetime.strptime(text, _ITCH_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise PurchaseRejected(
                f"itch purchase created_at is not a recognized timestamp: {text!r}"
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime(_RFC3339)


class ItchAdapter:
    """itch.io `PurchaseSource`: `fetch_purchases` (the live API call) + `normalize`.

    There is no webhook signature to verify here (see module docstring) — the
    trust boundary is simply "did `api.itch.io` return this purchase for this
    (game_id, email) just now", enforced entirely by `ItchPoller.tick` calling
    `fetch_purchases` and never trusting claim/CSV data alone.
    """

    platform = "itch"

    def __init__(
        self,
        *,
        api_key: str,
        api_base: str = "https://api.itch.io",
        http_get: Callable[[str, dict[str, str]], bytes] | None = None,
    ) -> None:
        self._api_key = api_key
        self._api_base = api_base
        self._http_get = http_get if http_get is not None else _default_http_get

    def fetch_purchases(self, game_id: str, email: str) -> list[dict[str, Any]]:
        """`GET {api_base}/games/{game_id}/purchases?email=<urlencoded>`.

        THIS is the sole issuance authority (OI-4): whatever this returns is
        the only thing `ItchPoller.tick` will ever normalize and issue for.
        Any transport failure, non-200 response, or unparseable/malformed
        body becomes `ItchApiError` — never a partial or guessed result.
        """
        url = f"{self._api_base}/games/{game_id}/purchases?email={quote(email, safe='')}"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            body = self._http_get(url, headers)
        except Exception as exc:
            # Covers a non-200 status from the real `_default_http_get`
            # (`urlopen` raises `urllib.error.HTTPError` on any non-2xx
            # response) as well as any other transport failure from an
            # injected `http_get` — both are "the API call failed", which is
            # exactly the condition `ItchPoller.tick` backs off on.
            raise ItchApiError(
                _scrub(
                    f"itch purchases request failed: {exc}",
                    email=email,
                    api_key=self._api_key,
                )
            ) from exc
        try:
            data = json.loads(body)
        except (ValueError, RecursionError) as exc:
            # ValueError covers json.JSONDecodeError; RecursionError covers
            # pathologically nested input — both are "bad JSON".
            raise ItchApiError(f"itch purchases response is not valid JSON: {exc}") from exc
        purchases = data.get("purchases") if isinstance(data, dict) else None
        if not isinstance(purchases, list):
            raise ItchApiError("itch purchases response has no 'purchases' list")
        return purchases

    def normalize(self, raw: dict[str, Any], *, email: str) -> NormalizedPurchase:
        """Turn one raw itch purchase dict into a `NormalizedPurchase`.

        `buyer_pubkey` is ALWAYS `None` — design decision 3: itch has no
        metadata/custom-field carrier like Stripe's checkout session, so
        every itch receipt is email-bound only, never transferable. Refund/
        cancel filtering is `ItchPoller.tick`'s job, not this method's — this
        only maps fields, it never decides whether a purchase is issuable.
        """
        if not isinstance(raw, dict):
            raise PurchaseRejected(f"itch purchase is not an object: {raw!r}")
        raw_id = raw.get("id")
        if isinstance(raw_id, bool) or not isinstance(raw_id, (str, int)):
            raise PurchaseRejected(f"itch purchase id is missing or not a scalar: {raw_id!r}")
        raw_game_id = raw.get("game_id")
        if isinstance(raw_game_id, bool) or not isinstance(raw_game_id, (str, int)):
            raise PurchaseRejected(
                f"itch purchase game_id is missing or not a scalar: {raw_game_id!r}"
            )
        purchase_id = str(raw_id)
        game_id = str(raw_game_id)
        purchased_at = _parse_itch_created_at(raw.get("created_at"))
        price = raw.get("price")
        return NormalizedPurchase(
            platform=self.platform,
            platform_purchase_id=purchase_id,
            buyer_identifier=email,
            identifier_type="email",
            buyer_pubkey=None,
            product_key=f"itch_{game_id}",
            purchased_at=purchased_at,
            amount=str(price) if price is not None else None,
            currency=raw.get("currency"),
        )


class ItchPoller:
    """Drains DUE claims once per `tick`, calling the live itch API as the
    sole issuance authority for each one (OI-4 — see module docstring).

    Concurrency (why there is no lock in this class, unlike `http.py`'s
    webhook critical section): this poller is the ONLY code path that ever
    processes `platform="itch"` purchases — there is no itch webhook, so
    nothing else can race it for an itch purchase id. Stripe's webhook lock
    (`http.py`'s `make_app`) protects `platform="stripe"` exclusively; the
    two platforms are disjoint in the Ledger's `(platform, purchase_id)` key
    space, so a tick and a concurrent Stripe webhook delivery can never
    contend for the same row, and sharing the webhook lock with the poller
    would be pointless (they never touch overlapping state). `run_forever`
    drives this class from exactly one daemon thread (`cli.py`'s `serve`),
    so within a single tick, two claims for the same (email, game) that
    surface the same purchase id are handled sequentially: the first
    iteration issues and durably records the receipt (the Ledger's
    `(platform, purchase_id)` PRIMARY KEY makes that record durable, T4), and
    the second claim's iteration sees `ledger.get_receipt` already populated
    and completes without re-issuing. The Ledger's own per-statement lock
    keeps every individual read/write atomic regardless of thread count.
    """

    def __init__(
        self,
        *,
        adapter: ItchAdapter,
        ledger: Ledger,
        core: IssuingCore,
        max_attempts: int = 10,
        backoff_base_seconds: int = 60,
    ) -> None:
        self._adapter = adapter
        self._ledger = ledger
        self._core = core
        self._max_attempts = max_attempts
        self._backoff_base_seconds = backoff_base_seconds

    def tick(self, *, now: datetime) -> None:
        """Drain every claim due at `now` (synchronous, fully testable).

        Pinned by the bridge plan — see the module/class docstrings for why
        the live API call is the only thing that can ever lead to
        `core.process` being invoked.
        """
        now_rfc3339 = now.strftime(_RFC3339)
        for claim in self._ledger.due_claims(now_rfc3339):
            try:
                completed = self._drain_claim(claim, now_rfc3339)
            except ItchApiError as exc:
                self._defer_or_exhaust(claim, now, api_failure=True, detail=str(exc))
                continue
            except Exception:
                # One claim's unexpected failure (e.g. a signing IssueError) must
                # neither abort the whole tick nor kill the sole poller thread:
                # log it and defer this claim to retry on the normal backoff.
                _log.exception(
                    "itch poller: unexpected error on claim %s; deferring",
                    purchase_id_for_log(claim.token),
                )
                self._defer_or_exhaust(claim, now)
                continue
            if not completed:
                self._defer_or_exhaust(claim, now)
                continue
            self._ledger.complete_claim(claim.token)

    def _drain_claim(self, claim: Claim, now_rfc3339: str) -> bool:
        """Fetch the claim's live purchases and issue for the actionable ones.
        Every API-confirmed purchase is independently processed, so one
        malformed purchase cannot prevent a later purchase in the same
        response from being issued and emailed.
        Raises ItchApiError on API failure."""
        purchases = self._adapter.fetch_purchases(claim.game_id, claim.email)
        completed = False
        retryable_failure = False
        for raw in purchases:
            if not isinstance(raw, dict):
                _log.warning(
                    "itch poller: skipping non-object purchase row for claim %s",
                    purchase_id_for_log(claim.token),
                )
                continue
            if raw.get("status") in _SKIP_STATUSES:
                continue
            try:
                normalized = self._adapter.normalize(raw, email=claim.email)
            except (PurchaseRejected, UnmappedProduct) as exc:
                # The API confirmed this purchase (OI-4 satisfied) but it can't be
                # normalized/mapped: dead-letter for triage; the claim still
                # completes below. Never re-issue or synthesize a receipt here.
                failed_claim = {
                    "claim": {"email": claim.email, "game_id": claim.game_id},
                    "purchase": raw,
                }
                self._ledger.add_dead_letter(
                    "itch",
                    None,
                    str(exc),
                    json.dumps(failed_claim),
                    now=now_rfc3339,
                )
                completed = True
                continue
            purchase_id = normalized.platform_purchase_id
            try:
                outcome = self._core.process(normalized)
            except (PurchaseRejected, UnmappedProduct) as exc:
                failed_claim = {
                    "claim": {"email": claim.email, "game_id": claim.game_id},
                    "purchase": raw,
                }
                self._ledger.add_dead_letter(
                    "itch",
                    purchase_id,
                    str(exc),
                    json.dumps(failed_claim),
                    now=now_rfc3339,
                )
                completed = True
                continue
            except Exception:
                # Do not let one transient signing/storage failure starve a
                # second purchase returned for this same claim. The claim stays
                # pending for retry after the remaining rows are attempted.
                _log.exception(
                    "itch poller: failed purchase %s; continuing", purchase_id_for_log(purchase_id)
                )
                retryable_failure = True
                continue
            completed = True
            if not outcome.duplicate:
                self._ledger.add_claim_receipts(claim.token, 1)
        return completed and not retryable_failure

    def _defer_or_exhaust(
        self, claim: Claim, now: datetime, *, api_failure: bool = False, detail: str | None = None
    ) -> None:
        # `detail` is the API error's own message, carried through so the
        # operator learns WHY. Without it the only signal a merchant who pasted
        # a bad API key ever sees is "itch API failure", repeated until the
        # claim is abandoned — the reason existed and was being discarded at
        # the handler. It arrives already scrubbed of the buyer's address and
        # the API key (see `_scrub`, applied where the message is built).
        safe_detail = detail
        if claim.attempts + 1 >= self._max_attempts:
            failure_kind = "API" if api_failure else "issuance/storage"
            failure_reason = "failed API attempts" if api_failure else "issuance/storage failures"
            _log.warning(
                "itch %s failure for game %s (attempt %d): %s; abandoning claim",
                failure_kind,
                claim.game_id,
                claim.attempts + 1,
                safe_detail or "no further detail",
            )
            abandoned = f"claim abandoned after {claim.attempts + 1} {failure_reason}"
            self._ledger.exhaust_claim_with_dead_letter(
                claim.token,
                platform="itch",
                purchase_id=None,
                reason=f"{abandoned}; last error: {safe_detail}" if safe_detail else abandoned,
                raw_json=json.dumps({"email": claim.email, "game_id": claim.game_id}),
                now=now.strftime(_RFC3339),
            )
            return
        if api_failure:
            _log.warning(
                "itch API failure for game %s (attempt %d): %s",
                claim.game_id,
                claim.attempts + 1,
                safe_detail or "no further detail",
            )
        delay_seconds = self._backoff_base_seconds * (2**claim.attempts)
        next_attempt_at = (now + timedelta(seconds=delay_seconds)).strftime(_RFC3339)
        self._ledger.defer_claim(claim.token, next_attempt_at=next_attempt_at)

    def run_forever(self, stop: threading.Event, interval_seconds: int) -> None:
        """Tick once, then wait `interval_seconds` (or until `stop` fires),
        forever. `stop.wait` doubles as the sleep and the shutdown signal."""
        while not stop.is_set():
            try:
                self.tick(now=datetime.now(UTC))
            except Exception:
                # Last-resort guard: tick already isolates per-claim failures, but a
                # failure in due_claims() itself must not kill the sole daemon thread.
                _log.exception("itch poller: tick failed; continuing")
            stop.wait(interval_seconds)
