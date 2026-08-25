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
proof, `check-artifact` for the bytes. This module contributes exactly one
authorisation check the CLI does not expose — whether the file it is about to
hand over is inside the grant's own scope — and it makes that check against
the FLOOR grant the receipt hash-binds, never against a later version an
attacker might supply. Because §18.3's ratchet forbids a later grant from
narrowing scope, the floor's scope is a subset of the effective one: reading
the floor is therefore strictly conservative, never permissive.

Refusals are verdicts, never exceptions. A gate that raises on hostile input
leaks which check failed through the shape of the crash, and §18.7 asks for
the opposite.
"""

from __future__ import annotations

import hashlib
import json
import shutil
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

#: `verify`'s `revocation` values that end the request. A transferred receipt
#: is no longer this holder's, which is the same answer as a revoked one.
REVOCATION_REFUSED = frozenset({"revoked", "transferred"})


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
    """

    audience: str
    archive_dir: Path
    trust_dir: Path
    anchor_policy: Path | None = None
    revocations: Path | None = None

    # -- the custodian's own file -------------------------------------------

    def challenge(self, *, receipt: Path, out_dir: Path) -> Path:
        """Mint a fresh challenge for this receipt, bound to this audience.

        The nonce is the custodian's own material, so a malformed challenge
        stays a loud error rather than a refusal: it would be the gate's bug,
        not the holder's request.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "challenge.json"
        _driver.run_cli_json(
            [
                "grant",
                "challenge",
                "--receipt",
                str(receipt),
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
        challenge: Path,
        response: Path,
        deliver_to: Path,
        offered_salt: str | None = None,
    ) -> Decision:
        """Decide whether to hand over the archived copy, in §18.7's order.

        `offered_salt` exists only to demonstrate a prohibition: the
        buyer-binding salt proves the binding to a verifier, and is exactly
        the wrong thing to hand a custodian, who would then be able to
        impersonate the holder everywhere. It is refused first, before any
        other check, so that the refusal cannot be read as a fallback.
        """
        if offered_salt is not None:
            return _refuse(
                "salt_disclosure_rejected",
                "the buyer-binding salt is not a redemption proof and is never accepted here",
            )

        verdict = self._verify_receipt(receipt, grant_view)
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
        if verdict.get("ok") is not True:
            return _refuse("receipt_not_ok", "the receipt did not verify")
        if verdict.get("grant") != "activated":
            return _refuse(
                "grant_not_activated",
                f"the sunset grant is {verdict.get('grant')}, so nothing is owed yet",
            )

        if not self._redemption_verified(receipt, challenge, response):
            return _refuse(
                "redemption_proof_invalid",
                "the response does not prove possession of this receipt's key for this archive",
            )

        served_from = self._archived_copy(receipt, grant_view)
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
            detail=f"delivered {delivered.name} against a verified receipt and an activated grant",
            delivered=delivered,
        )

    # -- the individual checks ----------------------------------------------

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
        for filename in _receipt_filenames(receipt):
            candidate = self.archive_dir / filename
            if not candidate.is_file():
                continue
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if permitted is not None and digest not in permitted:
                continue
            rc, report = _check_artifact(candidate, receipt)
            if rc == 0 and report.get("match") is True:
                return candidate
        return None


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
