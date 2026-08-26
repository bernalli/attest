"""demo/custodian.py — the archive gate, a reference implementation.

NON-NORMATIVE. This module is a demonstration, not part of the attest
protocol. It is deliberately outside the installed package: there is no
`attest custodian` command and there never will be, because a verb inside the
CLI would say "component" by its mere existence, and attest defines a receipt
format and a verifier, not a distribution system (§18.7, Appendix A). Nothing
here is required of a conforming implementation, and nothing here is covered
by the conformance corpus.

What it demonstrates: a custodian — an archive that already holds its own
independent copy of a work — deciding whether to hand that copy to whoever
turns up with a receipt, once the seller is gone and the rights holder's
sunset grant has been activated. The interesting half is the refusals.

Every decision that VERIFIES, AUTHENTICATES or SIGNS is delegated to the real
`attest` CLI: `verify` for the receipt and the grant evidence, `grant
challenge` for the nonce, `grant verify` for the audience-bound redemption
proof, `check-artifact` for the bytes. This module contributes what the CLI
does not: the POSSESSION and one-shot CONSUMPTION of the custodian's own
challenges — a challenge is minted into the custodian's own directory,
remembered there, and spent on the request that uses it — and the check that
the file it is about to hand over is inside the grant's own scope. A request
therefore never carries a challenge, only an answer to one this custodian
already issued, which is what makes a response good exactly once.

The scope check is made against the FLOOR grant the receipt hash-binds,
never against a later version an attacker might supply. Because §18.3's
ratchet forbids a later grant from narrowing scope, the floor's scope is a
subset of the effective one: reading the floor is therefore strictly
conservative, never permissive.

Honesty about that check: it is belt over braces, not the last line of
defence it might look like. §18.4's coverage predicate already refuses to
activate a grant that does not cover the receipt's work, artifact by
artifact, so every construction tried against this gate was turned away by
the verifier before the filter here was ever consulted. It stays because a
gate that hands over bytes should decide for itself that it is allowed to,
not because anything is known to slip past without it.

Both files the requester owns — the receipt and the grant evidence — are
frozen into storage the gate owns for the length of a call, because a path
that is read more than once is a path that can change between reads.

Refusals are verdicts, never exceptions. A gate that raises on hostile input
leaks which check failed through the shape of the crash, and §18.7 asks for
the opposite. The boundary is hostile input, and it is drawn deliberately:
paths the OPERATOR supplies — where to mint a challenge, where to deliver —
stay loud, because a custodian misconfigured by its own operator should fail
where the operator can see it, not answer a stranger with a polite refusal.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from demo import _driver

#: Every reason a `Decision` may carry. A closed vocabulary, so a new failure
#: mode has to be named deliberately instead of slipping in as a message.
REASONS = frozenset(
    {
        "served",
        "receipt_not_ok",
        "revocation_blocked",
        "grant_not_activated",
        "redemption_proof_invalid",
        "salt_disclosure_rejected",
        "artifact_out_of_scope",
    }
)

#: `verify`'s `revocation` values that end the request. Today's CLI exposes a
#: revocation view but no transfer view, so the verdict's `revocation` member
#: cannot currently read `transferred`; if it ever does, it is still the same
#: refusal as a revoked receipt. The transfer itself is not invisible — see
#: `TRANSFERRED_UNBACKED` below, which is how the gate sees it today.
REVOCATION_REFUSED = frozenset({"revoked", "transferred"})

#: The verifier warning that says, in so many words, "a transfer of this
#: receipt was asserted and this verifier had no transfer view to resolve it
#: against". It is worth refusing on because of who can produce it: `verify`
#: emits it only for a record that authenticates against the ISSUER's own key
#: AND names THIS receipt_id, so a passer-by cannot fabricate one. That is the
#: opposite of the generic `invalid_revocation_ignored` state, which anyone
#: can provoke and which this gate therefore ignores on purpose.
TRANSFERRED_UNBACKED = "transferred_revocation_unbacked"


@dataclass(frozen=True)
class Decision:
    """What the gate decided, and why. `detail` is a human sentence for the
    narration and is never load-bearing: the machine-readable answer is
    `served` plus `reason`."""

    served: bool
    reason: str
    detail: str = ""
    delivered: Path | None = None

    def __post_init__(self) -> None:
        if self.reason not in REASONS:
            raise ValueError(f"unknown decision reason: {self.reason!r}")


def _refuse(reason: str, detail: str) -> Decision:
    return Decision(served=False, reason=reason, detail=detail)


@dataclass(frozen=True)
class Custodian:
    """An archive that holds its own copy of the works it may be asked for.

    `audience` is the custodian's own lowercase DNS domain, and it is the
    reason a redemption proof cannot be replayed elsewhere: it is inside the
    preimage the holder signs (§18.7).

    `challenge_dir` is the custodian's own memory: the challenges it has
    minted and not yet spent live there, one per receipt at most.
    """

    audience: str
    archive_dir: Path
    trust_dir: Path
    challenge_dir: Path
    anchor_policy: Path | None = None
    revocations: Path | None = None

    # -- the custodian's own file -------------------------------------------

    def challenge(self, *, receipt: Path) -> Path:
        """Mint a fresh challenge for this receipt, bound to this audience,
        and keep it.

        The file is written inside `challenge_dir` under the receipt's own
        id: the holder is handed its CONTENTS, while the custodian keeps the
        copy it will later spend. At most one challenge is outstanding per
        receipt, so minting a second one supersedes the first — the answer to
        a superseded challenge is no longer an answer to anything.

        The nonce and the file are both the custodian's own material, so a
        receipt that cannot even name a challenge here stays a loud error
        rather than a refusal: nothing has been decided about a request yet.
        """
        # `challenge` snapshots too: it derives the custodian-owned filename and
        # asks the CLI to read the same requester-owned receipt. Without a frozen
        # copy, a mid-call swap could key one receipt and mint a challenge for
        # another.
        with self._receipt_snapshot(receipt) as frozen_receipt:
            if frozen_receipt is None:
                raise ValueError(f"{receipt} does not name a receipt this custodian can challenge")
            receipt_id = _receipt_id(frozen_receipt)
            out = None if receipt_id is None else self._challenge_file(receipt_id)
            if out is None:
                raise ValueError(f"{receipt} does not name a receipt this custodian can challenge")
            _driver.run_cli_json(
                [
                    "grant",
                    "challenge",
                    "--receipt",
                    str(frozen_receipt),
                    "--audience",
                    self.audience,
                    "--out",
                    str(out),
                ]
            )
            return out

    # -- the request --------------------------------------------------------

    def redeem(
        self,
        *,
        receipt: Path,
        grant_view: Path,
        response: Path,
        deliver_to: Path,
        offered_salt: str | None = None,
    ) -> Decision:
        """Decide whether to hand over the archived copy, in §18.7's order.

        `offered_salt` exists only to demonstrate a prohibition: the
        buyer-binding salt proves the binding to a verifier, and is exactly
        the wrong thing to hand a custodian, who would then be able to
        impersonate the holder everywhere. Once the requester-owned receipt
        has been frozen, it is refused before any other semantic check, so
        that the refusal cannot be read as a fallback.
        """
        with (
            self._receipt_snapshot(receipt) as frozen_receipt,
            self._frozen(grant_view, "grant-view.json") as frozen_view,
        ):
            if frozen_receipt is None:
                return _refuse("receipt_not_ok", "the receipt could not be read as an envelope")
            if frozen_view is None:
                # No evidence the gate can hold still is no evidence at all,
                # and nothing is owed without an activated grant.
                return _refuse(
                    "grant_not_activated",
                    "the grant evidence could not be read",
                )

            if offered_salt is not None:
                return _refuse(
                    "salt_disclosure_rejected",
                    "the buyer-binding salt is not a redemption proof and is never accepted here",
                )

            verdict = self._verify_receipt(frozen_receipt, frozen_view)
            if verdict is None:
                return _refuse("receipt_not_ok", "the receipt could not be read as an envelope")

            # Order matters, and not the order the checks are written in the spec.
            # A revoked receipt is ALSO `ok: false`, so asking `ok` first would
            # report every revocation as a generic verification failure and lose
            # the only fact the holder can act on. Authenticity still comes first:
            # `revocation` is only meaningful once the envelope is known to be the
            # issuer's own, or a forged receipt could pick its own refusal.
            authentic = verdict.get("signature") == "valid" and verdict.get("schema") == "valid"
            if not authentic:
                return _refuse("receipt_not_ok", "the receipt is not a valid signed envelope")
            if verdict.get("revocation") in REVOCATION_REFUSED:
                return _refuse(
                    "revocation_blocked",
                    f"the receipt is {verdict.get('revocation')}",
                )
            if TRANSFERRED_UNBACKED in _verdict_warnings(verdict):
                return _refuse(
                    "revocation_blocked",
                    "the receipt has been transferred away, so this holder is no longer "
                    "the one owed",
                )
            if verdict.get("ok") is not True:
                return _refuse("receipt_not_ok", "the receipt did not verify")
            if verdict.get("grant") != "activated":
                return _refuse(
                    "grant_not_activated",
                    f"the sunset grant is {verdict.get('grant')}, so nothing is owed yet",
                )

            # The challenge is the custodian's own file, and this is where it is
            # spent. A request that answers nobody's challenge, or answers a
            # superseded or already-spent one, is flattened into the same refusal
            # as a bad signature.
            if not self._redemption_proven(frozen_receipt, response):
                return _refuse(
                    "redemption_proof_invalid",
                    "the response does not prove possession of this receipt's key for this archive",
                )

            served_from = self._archived_copy(frozen_receipt, frozen_view)
            if served_from is None:
                return _refuse(
                    "artifact_out_of_scope",
                    "no archived copy matches both this receipt and the grant's scope",
                )

            deliver_to.mkdir(parents=True, exist_ok=True)
            delivered = deliver_to / served_from.name
            shutil.copy(served_from, delivered)
            return Decision(
                served=True,
                reason="served",
                detail=(
                    f"delivered {delivered.name} against a verified receipt and an activated grant"
                ),
                delivered=delivered,
            )

    # -- the individual checks ----------------------------------------------

    @contextmanager
    def _receipt_snapshot(self, receipt: Path) -> Iterator[Path | None]:
        """Freeze requester-owned receipt bytes for one custodian operation."""
        with self._frozen(receipt, "receipt.attest.json") as snapshot:
            yield snapshot

    @contextmanager
    def _frozen(self, source: Path, name: str) -> Iterator[Path | None]:
        """Freeze a requester-owned file for the length of one operation.

        Anything the requester holds is read more than once during a redeem —
        the receipt by `verify`, by the redemption proof and by the artifact
        step; the grant evidence by `verify` and by the scope filter — and a
        path re-read is a path that can change between reads. Copying once
        into storage the gate owns makes "the thing that was checked" and
        "the thing that was used" the same bytes by construction.

        Yields `None` when the source cannot be read at all, so the caller
        reports a refusal instead of letting the error escape.
        """
        try:
            payload = source.read_bytes()
        except (OSError, ValueError):
            yield None
            return

        self.challenge_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="attest-custodian-frozen-", dir=self.challenge_dir
        ) as scratch:
            snapshot = Path(scratch) / name
            snapshot.write_bytes(payload)
            yield snapshot

    def _verify_receipt(self, receipt: Path, grant_view: Path) -> dict[str, Any] | None:
        """The receipt and the grant evidence, through the real verifier.

        Returns `None` when `verify` could not produce a verdict at all — a
        file that is not an envelope — which the caller reports as a plain
        refusal rather than letting the exception escape.
        """
        argv = [
            "verify",
            str(receipt),
            "--trust-dir",
            str(self.trust_dir),
            "--grant-view",
            str(grant_view),
        ]
        if self.anchor_policy is not None:
            argv += ["--anchor-policy", str(self.anchor_policy)]
        if self.revocations is not None:
            argv += ["--revocations", str(self.revocations)]
        _rc, stdout, _stderr = _driver.run_cli(argv)
        try:
            verdict = json.loads(stdout)
        except json.JSONDecodeError:
            return None
        return verdict if isinstance(verdict, dict) else None

    def _challenge_file(self, receipt_id: str) -> Path | None:
        """Where this receipt's outstanding challenge lives, or `None` when
        the id could not name a file inside `challenge_dir`.

        A receipt is the requester's own file until the verifier has spoken,
        so its `receipt_id` is the requester's string: a separator or a `..`
        in it must not be able to aim the custodian's own bookkeeping
        somewhere else.
        """
        name = f"{receipt_id}.json"
        candidate = self.challenge_dir / name
        if candidate.parent != self.challenge_dir or candidate.name != name:
            return None
        return candidate

    def _redemption_proven(self, receipt: Path, response: Path) -> bool:
        """Spend this receipt's outstanding challenge on this response.

        The challenge leaves its receipt-id path BEFORE the answer is known,
        so that pending challenge is consumed by USE and not by success: a
        holder who answers wrongly, or a thief who tries, burns it either way.
        A later mint at the same receipt-id path is a different challenge and
        is not touched by this claim, so a legitimate holder simply asks for
        another one. One round trip buys the property that no response is ever
        worth replaying.
        """
        receipt_id = _receipt_id(receipt)
        pending = None if receipt_id is None else self._challenge_file(receipt_id)
        if pending is None:
            return False
        if not self.challenge_dir.is_dir():
            return False
        try:
            with tempfile.TemporaryDirectory(
                prefix="attest-custodian-claim-", dir=self.challenge_dir
            ) as scratch:
                spent = Path(scratch) / pending.name
                try:
                    # Same-directory rename is the claim: whoever moves the
                    # pending path owns those bytes, and a later mint recreates
                    # a separate outstanding challenge.
                    pending.replace(spent)
                except FileNotFoundError:
                    return False
                except OSError:
                    return False

                # Defence in depth, and the reason it is not redundant: owning the
                # directory is what makes the audience right by construction, and
                # that ownership is an assumption about the filesystem, not
                # something the code can see. Two custodians sharing a directory
                # are keyed by the same `receipt_id` and would read each other's
                # file, which is precisely the cross-archive replay §18.7 exists to
                # forbid. One comparison costs nothing when the directory is
                # private and restores the binding when it is not.
                if _challenge_audience(spent) != self.audience:
                    return False
                return self._redemption_verified(receipt, spent, response)
        except (OSError, ValueError):
            return False

    def _redemption_verified(self, receipt: Path, challenge: Path, response: Path) -> bool:
        """§18.7's audience-bound proof, through the real verifier.

        Every way a holder's response can be wrong — a foreign key, a
        response minted for another archive, a malformed file — collapses to
        the same answer here, which is the property the spec asks for.
        """
        rc, _stdout, _stderr = _driver.run_cli(
            [
                "grant",
                "verify",
                "--receipt",
                str(receipt),
                "--challenge",
                str(challenge),
                "--response",
                str(response),
            ]
        )
        return rc == 0

    def _archived_copy(self, receipt: Path, grant_view: Path) -> Path | None:
        """The file to hand over, or `None` if there isn't a legitimate one.

        Two conditions, both required: the bytes must be what the receipt
        says were bought (`check-artifact`, the CLI's own answer), and their
        hash must be inside the grant's scope (the one authorisation the CLI
        does not expose — see the module docstring on why the floor grant is
        the conservative place to read it).
        """
        permitted = _granted_artifacts(grant_view)
        archive_root = self.archive_dir.resolve()
        for filename in _receipt_filenames(receipt):
            # Resolution itself is hostile ground: a filename carrying a NUL
            # byte makes `resolve()` raise `ValueError` before containment is
            # ever considered. A candidate the filesystem will not even name
            # leaves the running exactly like one that is missing.
            try:
                candidate = (self.archive_dir / filename).resolve()
                candidate.relative_to(archive_root)
            except (OSError, ValueError):
                continue
            if not candidate.is_file():
                continue
            try:
                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            except OSError:
                # A copy the process cannot read leaves the running exactly
                # like one that is missing: the loop above already treats
                # absence that way, and unreadability is the same fact.
                continue
            if permitted is not None and digest not in permitted:
                continue
            rc, report = _check_artifact(candidate, receipt)
            if rc == 0 and report.get("match") is True:
                return candidate
        return None


def _challenge_audience(path: Path) -> str | None:
    """The audience a minted challenge names, or `None` if it does not name
    one. Tolerant by construction: this is read on the refusal path, and a
    reader that raises there would leak which check failed."""
    challenge = _read_json(path)
    if not isinstance(challenge, dict):
        return None
    audience = challenge.get("audience")
    return audience if isinstance(audience, str) else None


def _check_artifact(candidate: Path, receipt: Path) -> tuple[int, dict[str, Any]]:
    rc, stdout, _stderr = _driver.run_cli(
        ["check-artifact", str(candidate), "--receipt", str(receipt)]
    )
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        return rc, {}
    return rc, report if isinstance(report, dict) else {}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _verdict_warnings(verdict: dict[str, Any]) -> list[str]:
    warnings = verdict.get("warnings")
    if not isinstance(warnings, list):
        return []
    return [warning for warning in warnings if isinstance(warning, str)]


def _receipt_id(receipt: Path) -> str | None:
    """The id the receipt names, or `None` when it names none.

    Read for bookkeeping only — which challenge belongs to which request —
    never as a verification: by the time `redeem` uses it, `verify` has
    already said the envelope is the issuer's own.
    """
    envelope = _read_json(receipt)
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    receipt_id = payload.get("receipt_id") if isinstance(payload, dict) else None
    return receipt_id if isinstance(receipt_id, str) else None


def _receipt_filenames(receipt: Path) -> list[str]:
    """The artifact filenames the receipt names, in its own order.

    Reading a field to decide which file to look for is not a verification —
    the verification is `check-artifact`, which runs against the receipt
    itself and is the only thing the decision rests on.
    """
    envelope = _read_json(receipt)
    if not isinstance(envelope, dict):
        return []
    payload = envelope.get("payload")
    work = payload.get("work") if isinstance(payload, dict) else None
    artifacts = work.get("artifacts") if isinstance(work, dict) else None
    if not isinstance(artifacts, list):
        return []
    return [
        entry["filename"]
        for entry in artifacts
        if isinstance(entry, dict) and isinstance(entry.get("filename"), str)
    ]


def _granted_artifacts(grant_view: Path) -> frozenset[str] | None:
    """The artifact hashes the FLOOR grant permits, or `None` when the grant
    scopes by series instead and there is no hash list to check against."""
    view = _read_json(grant_view)
    grant = view.get("grant") if isinstance(view, dict) else None
    scope = grant.get("scope") if isinstance(grant, dict) else None
    artifacts = scope.get("artifacts") if isinstance(scope, dict) else None
    if not isinstance(artifacts, list) or not artifacts:
        return None
    return frozenset(h for h in artifacts if isinstance(h, str))
