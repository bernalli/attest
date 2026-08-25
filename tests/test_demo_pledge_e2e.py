"""The archive gate's refusal matrix — `demo/custodian.py` (Task V-D.2).

A custodian holds an independent copy of a work and hands it to a holder ONLY
against a valid receipt, an activated sunset grant, and an audience-bound
redemption proof. This file pins what it must REFUSE, one refusal per test,
because a gate is defined by what it turns away.

The world these tests run against is built here, by driving the real CLI, and
is deliberately INDEPENDENT of the world `demo/pledge_dies.py` narrates. That
duplication is the point: if the demo's construction ever drifts, these tests
still pin the custodian's behaviour against a separately-built world, the same
reasoning that keeps the seeded-anchor fixtures independent of one another.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from attest import cli, issue, keys, pq, revocation, ulid
from demo import custodian as custodian_mod
from demo.custodian import Custodian, Decision

PUBLISHER = "pub.pledge.example"
PUB_KID = f"{PUBLISHER}/keys/bootstrap-1#ed25519-1"
STORE = "store.pledge.example"
STORE_KID = f"{STORE}/keys/bootstrap-1#ed25519-1"
ARCHIVE = "archive.holders.example"
OTHER_ARCHIVE = "other-archive.example"
EPOCH = "2020-01-01T00:00:00Z"
SERIES = f"{STORE}/works/PLEDGE-001"
FILENAME = "pledged-game-1.0-setup.bin"
WORK_BYTES = b"PLEDGE-DEMO-BINARY-" + b"\x00\x01\x02\x03" * 8
LEGAL_BYTES = b"DRAFT preservation pledge prose - requires legal counsel.\n"


def _cli(argv: list[str]) -> dict[str, Any]:
    """Run a setup verb that must succeed and return its stdout JSON."""
    import contextlib
    import io

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv)
    if rc != 0:
        raise RuntimeError(
            f"setup step failed ({rc}): attest {' '.join(argv[:2])}: {err.getvalue().strip()}"
        )
    parsed: dict[str, Any] = json.loads(out.getvalue())
    return parsed


@dataclass(frozen=True)
class World:
    """Everything the refusal matrix needs, built once by the real CLI."""

    root: Path
    receipt: Path
    trust_dir: Path
    archive_dir: Path
    buyer_seed: Path
    foreign_seed: Path
    salt_b64u: str
    grant_view_dormant: Path
    grant_view_active: Path
    revocations: Path
    revocable_receipt: Path
    revocable_revocations: Path
    work_sha256: str


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> World:
    root = tmp_path_factory.mktemp("pledge-world")
    pub, store, buyer, arch = (root / n for n in ("publisher", "store", "buyer", "custodian"))
    trust = root / "trust"
    for d in (pub, store, buyer, arch, trust):
        d.mkdir(parents=True, exist_ok=True)

    # --- the rights holder, who outlives the store ---------------------------
    pub_seed, pub_mldsa = pub / "publisher.seed", pub / "publisher.mldsa.json"
    _cli(
        [
            "keygen",
            "--seed-out",
            str(pub_seed),
            "--pub-out",
            str(pub / "publisher.pub"),
            "--hybrid",
            "--mldsa-out",
            str(pub_mldsa),
        ]
    )
    _cli(
        [
            "manifest",
            "init",
            "--issuer",
            PUBLISHER,
            "--kid",
            PUB_KID,
            "--seed",
            str(pub_seed),
            "--valid-from",
            EPOCH,
            "--issued-at",
            EPOCH,
            "--mldsa-key",
            str(pub_mldsa),
            "--out",
            str(trust / "publisher.json"),
        ]
    )

    # --- the store ------------------------------------------------------------
    store_seed, store_mldsa = store / "issuer.seed", store / "issuer.mldsa.json"
    _cli(
        [
            "keygen",
            "--seed-out",
            str(store_seed),
            "--pub-out",
            str(store / "issuer.pub"),
            "--hybrid",
            "--mldsa-out",
            str(store_mldsa),
        ]
    )
    _cli(
        [
            "manifest",
            "init",
            "--issuer",
            STORE,
            "--kid",
            STORE_KID,
            "--seed",
            str(store_seed),
            "--valid-from",
            EPOCH,
            "--issued-at",
            EPOCH,
            "--mldsa-key",
            str(store_mldsa),
            "--out",
            str(trust / "store.json"),
        ]
    )

    # --- the work, and the custodian's own independent copy -------------------
    work_sha = hashlib.sha256(WORK_BYTES).hexdigest()
    (arch / FILENAME).write_bytes(WORK_BYTES)
    entry = {
        "role": "installer",
        "platform": "linux-x86_64",
        "filename": FILENAME,
        "size_bytes": len(WORK_BYTES),
        "sha256": work_sha,
    }
    artifacts_json = store / "artifacts.json"
    artifacts_json.write_text(json.dumps([entry]), encoding="utf-8")
    _cli(
        [
            "manifest",
            "artifacts",
            "--in",
            str(trust / "store.json"),
            "--issuer",
            STORE,
            "--series",
            SERIES,
            "--version",
            "1",
            "--manifest-version",
            "1",
            "--released-at",
            EPOCH,
            "--artifacts",
            str(artifacts_json),
            "--signing-kid",
            STORE_KID,
            "--signing-seed",
            str(store_seed),
            "--mldsa-key",
            str(store_mldsa),
            "--out",
            str(store / "artifact-manifest.json"),
        ]
    )

    # --- the pledge -----------------------------------------------------------
    legal = pub / "legal.txt"
    legal.write_bytes(LEGAL_BYTES)
    grant_path = pub / "grant.json"
    grant_report = _cli(
        [
            "grant",
            "issue",
            "--grant-version",
            "1",
            "--publisher",
            PUBLISHER,
            "--artifact",
            work_sha,
            "--permission",
            "deliver-to-holder",
            "--mode",
            "publisher-declaration",
            "--mode",
            "fixed-date",
            "--fixed-date",
            "2031-01-01T00:00:00Z",
            "--legal-text-uri",
            f"https://{PUBLISHER}/pledge/grant-v1.json",
            "--legal-text-sha256",
            hashlib.sha256(LEGAL_BYTES).hexdigest(),
            "--jurisdiction",
            "IT",
            "--issued-at",
            EPOCH,
            "--seed",
            str(pub_seed),
            "--kid",
            PUB_KID,
            "--mldsa-seed",
            str(pub_mldsa),
            "--out",
            str(grant_path),
        ]
    )
    grant_sha = grant_report["grant_sha256"]

    # --- the receipt: the buyer holds a key (§18.6) ---------------------------
    buyer_seed = buyer / "buyer.seed"
    _cli(["keygen", "--seed-out", str(buyer_seed), "--pub-out", str(buyer / "buyer.pub")])
    buyer_pub = keys.b64u_decode((buyer / "buyer.pub").read_text().strip())
    salt = os.urandom(16)
    salt_b64u = keys.b64u(salt)
    salt_path = buyer / "receipt.salt"
    salt_path.write_text(salt_b64u, encoding="utf-8")

    payload = issue.build_payload(
        issuer_id=STORE,
        display_name="The Store That Pledged",
        buyer_identifier="casey@example.com",
        buyer_identifier_type="email",
        buyer_salt=salt,
        buyer_pubkey=buyer_pub,
        title="Pledged Game",
        publisher="Indie Games Co-op",
        identifiers={"issuer_sku": "PLEDGE-001"},
        artifact_series=SERIES,
        terms_uri=f"https://{STORE}/attest/license-templates/standard-v1",
        legal_text_sha256=hashlib.sha256(LEGAL_BYTES).hexdigest(),
        artifacts=[entry],
        revocability="none",
        drm="drm-free",
        end_of_life="sunset-grant",
        eol_commitment_uri=f"https://{PUBLISHER}/pledge/grant-v1.json",
        eol_commitment_sha256=grant_sha,
        publisher_id=PUBLISHER,
        preservation_pledge={
            "pledge": "sunset-grant-v1",
            "grant_uri": f"https://{PUBLISHER}/pledge/grant-v1.json",
            "grant_sha256": grant_sha,
        },
        attest_version="0.2",
    )
    payload_path = store / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    receipt = buyer / "receipt.attest.json"
    _cli(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(store_seed),
            "--kid",
            STORE_KID,
            "--salt",
            str(salt_path),
            "--attest-version",
            "0.2",
            "--mldsa-key",
            str(store_mldsa),
            "--out",
            str(receipt),
        ]
    )
    receipt_id = json.loads(receipt.read_text())["payload"]["receipt_id"]

    # --- the trigger: the rights holder declares the cessation ----------------
    decl_path = pub / "declaration.json"
    _cli(
        [
            "grant",
            "declare",
            "--publisher",
            PUBLISHER,
            "--artifact",
            work_sha,
            "--declared-at",
            "2027-01-01T00:00:00Z",
            "--seed",
            str(pub_seed),
            "--kid",
            PUB_KID,
            "--mldsa-seed",
            str(pub_mldsa),
            "--out",
            str(decl_path),
        ]
    )

    grant_doc = json.loads(grant_path.read_text())
    dormant = buyer / "grant-view-dormant.json"
    dormant.write_text(json.dumps({"grant": grant_doc}), encoding="utf-8")
    active = buyer / "grant-view-active.json"
    active.write_text(
        json.dumps({"grant": grant_doc, "declarations": [json.loads(decl_path.read_text())]}),
        encoding="utf-8",
    )

    # --- a revocation feed that revokes this very receipt ---------------------
    mldsa_obj = json.loads(store_mldsa.read_text())
    revoker = pq.HybridSigningKeys(
        ed=keys.from_seed(keys.b64u_decode(store_seed.read_text().strip())),
        mldsa=pq.MLDSAKeyPair(
            sk=keys.b64u_decode(mldsa_obj["sk"]), pub=keys.b64u_decode(mldsa_obj["pub"])
        ),
    )
    record = revocation.build_record(
        receipt_id, "revoked", "2027-06-01T00:00:00Z", revoker, STORE_KID
    )
    revocations = buyer / "revocations.json"
    revocations.write_text(json.dumps([record]), encoding="utf-8")

    # --- a revocable twin, so `revoked` is reachable at all -------------------
    # `revocability: "none"` makes the first receipt irrevocable BY DESIGN: a
    # record against it is reported as `invalid_revocation_ignored`, never as
    # `revoked`. A second receipt under `policy` is the only honest way to
    # exercise the gate's revocation branch.
    revocable_payload = dict(payload)
    revocable_payload["license"] = dict(payload["license"])
    revocable_payload["license"]["revocability"] = "policy"
    revocable_payload["receipt_id"] = ulid.generate()
    revocable_payload_path = store / "payload-revocable.json"
    revocable_payload_path.write_text(json.dumps(revocable_payload), encoding="utf-8")
    revocable_receipt = buyer / "receipt-revocable.attest.json"
    _cli(
        [
            "issue",
            "--payload",
            str(revocable_payload_path),
            "--seed",
            str(store_seed),
            "--kid",
            STORE_KID,
            "--salt",
            str(salt_path),
            "--attest-version",
            "0.2",
            "--mldsa-key",
            str(store_mldsa),
            "--out",
            str(revocable_receipt),
        ]
    )
    revocable_id = json.loads(revocable_receipt.read_text())["payload"]["receipt_id"]
    revocable_revocations = buyer / "revocations-revocable.json"
    revocable_revocations.write_text(
        json.dumps(
            [
                revocation.build_record(
                    revocable_id, "revoked", "2027-06-01T00:00:00Z", revoker, STORE_KID
                )
            ]
        ),
        encoding="utf-8",
    )

    foreign_seed = root / "foreign.seed"
    _cli(["keygen", "--seed-out", str(foreign_seed), "--pub-out", str(root / "foreign.pub")])

    return World(
        root=root,
        receipt=receipt,
        trust_dir=trust,
        archive_dir=arch,
        buyer_seed=buyer_seed,
        foreign_seed=foreign_seed,
        salt_b64u=salt_b64u,
        grant_view_dormant=dormant,
        grant_view_active=active,
        revocations=revocations,
        revocable_receipt=revocable_receipt,
        revocable_revocations=revocable_revocations,
        work_sha256=work_sha,
    )


def _gate(world: World, **overrides: Any) -> Custodian:
    kwargs: dict[str, Any] = {
        "audience": ARCHIVE,
        "archive_dir": world.archive_dir,
        "trust_dir": world.trust_dir,
    }
    kwargs.update(overrides)
    return Custodian(**kwargs)


def _respond(world: World, challenge: Path, out: Path, seed: Path | None = None) -> Path:
    _cli(
        [
            "grant",
            "respond",
            "--challenge",
            str(challenge),
            "--holder-seed",
            str(seed or world.buyer_seed),
            "--out",
            str(out),
        ]
    )
    return out


# --------------------------------------------------------------------------
# The one case that must succeed — without it the refusals prove nothing.
# --------------------------------------------------------------------------


def test_a_valid_redemption_is_served(world: World, tmp_path: Path) -> None:
    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is True
    assert decision.reason == "served"
    assert decision.delivered is not None
    assert decision.delivered.read_bytes() == WORK_BYTES


# --------------------------------------------------------------------------
# The refusal matrix, one reason per test.
# --------------------------------------------------------------------------


def test_the_salt_is_refused_as_a_redemption_proof(world: World, tmp_path: Path) -> None:
    """§18.7 forbids the buyer-binding salt as a redemption proof. The gate
    must refuse it even when everything else about the request is valid —
    that is what makes it a prohibition rather than a fallback."""
    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
        offered_salt=world.salt_b64u,
    )

    assert decision.served is False
    assert decision.reason == "salt_disclosure_rejected"


def test_a_dormant_grant_is_refused(world: World, tmp_path: Path) -> None:
    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_dormant,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "grant_not_activated"


def test_a_tampered_receipt_is_refused(world: World, tmp_path: Path) -> None:
    tampered = tmp_path / "tampered.attest.json"
    envelope = json.loads(world.receipt.read_text())
    envelope["payload"]["work"]["title"] = "Something Else Entirely"
    tampered.write_text(json.dumps(envelope), encoding="utf-8")

    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=tampered,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "receipt_not_ok"


def test_a_revoked_receipt_is_refused(world: World, tmp_path: Path) -> None:
    """An archive gate that never consults revocation is a weaker gate: the
    receipt still verifies, and the grant is still activated, but the deal it
    records has been undone."""
    gate = _gate(world, revocations=world.revocable_revocations)
    challenge = gate.challenge(receipt=world.revocable_receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.revocable_receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "revocation_blocked"


def test_a_bogus_revocation_record_cannot_deny_an_irrevocable_receipt(
    world: World, tmp_path: Path
) -> None:
    """The gate refuses on `revoked`/`transferred` and on nothing else.

    Anyone can publish a record naming someone else's receipt. Against an
    irrevocable receipt the verifier reports `invalid_revocation_ignored`, and
    a gate that treated "something was ignored" as a refusal would hand every
    passer-by a denial-of-service against a holder they have no relationship
    with. The record is noise; the delivery happens.
    """
    gate = _gate(world, revocations=world.revocations)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is True
    assert decision.reason == "served"


def test_a_proof_signed_by_a_foreign_key_is_refused(world: World, tmp_path: Path) -> None:
    """The attacker holds the PUBLIC bundle but not the buyer's seed."""
    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "forged.json", seed=world.foreign_seed)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"


def test_a_proof_minted_for_another_custodian_is_refused(world: World, tmp_path: Path) -> None:
    """The audience is inside the signed preimage, so a response the holder
    legitimately produced for one archive cannot be replayed at another."""
    elsewhere = _gate(world, audience=OTHER_ARCHIVE)
    other_challenge = elsewhere.challenge(receipt=world.receipt, out_dir=tmp_path / "elsewhere")
    replayed = _respond(world, other_challenge, tmp_path / "replayed.json")

    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=replayed,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"


def test_an_archive_copy_that_does_not_match_the_receipt_is_refused(
    world: World, tmp_path: Path
) -> None:
    """The custodian's own copy drifted. Everything else is valid; the bytes
    are not the bytes that were bought, so they are not served."""
    drifted = tmp_path / "drifted-archive"
    drifted.mkdir()
    (drifted / FILENAME).write_bytes(WORK_BYTES + b"tampered")

    gate = _gate(world, archive_dir=drifted)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "artifact_out_of_scope"


# --------------------------------------------------------------------------
# Properties that hold across the whole matrix.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("salt", "salt_disclosure_rejected"),
        ("dormant", "grant_not_activated"),
        ("foreign_key", "redemption_proof_invalid"),
    ],
)
def test_a_refusal_delivers_no_bytes(
    world: World, tmp_path: Path, case: str, expected: str
) -> None:
    """The canary: whatever the reason, the destination stays empty. A gate
    that refuses in its report but copies the file anyway is not a gate."""
    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    seed = world.foreign_seed if case == "foreign_key" else None
    response = _respond(world, challenge, tmp_path / "response.json", seed=seed)
    deliver_to = tmp_path / "out"

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_dormant if case == "dormant" else world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=deliver_to,
        offered_salt=world.salt_b64u if case == "salt" else None,
    )

    assert decision.reason == expected
    assert decision.served is False
    assert decision.delivered is None
    assert not deliver_to.exists() or not any(deliver_to.iterdir())


def test_every_decision_reason_belongs_to_the_closed_vocabulary(
    world: World, tmp_path: Path
) -> None:
    """§18.7's refusals are a vocabulary, not free text: a new failure mode
    must be named deliberately, not slipped in as a message."""
    assert custodian_mod.REASONS == frozenset(
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
    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)
    response = _respond(world, challenge, tmp_path / "response.json")
    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=response,
        deliver_to=tmp_path / "out",
    )
    assert decision.reason in custodian_mod.REASONS


def test_the_revocation_vocabulary_covers_transfer_as_well_as_revocation() -> None:
    """A transferred receipt is no longer the holder's, and the gate must
    treat it exactly like a revoked one. Reachable only with a transfer view,
    which this matrix does not build, so the intent is pinned here."""
    assert custodian_mod.REVOCATION_REFUSED == frozenset({"revoked", "transferred"})


def test_a_hostile_request_never_raises(world: World, tmp_path: Path) -> None:
    """Every refusal is a verdict, never an exception: a gate that raises on
    hostile input leaks which check failed through the shape of the crash."""
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json at all", encoding="utf-8")

    gate = _gate(world)
    challenge = gate.challenge(receipt=world.receipt, out_dir=tmp_path)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        challenge=challenge,
        response=garbage,
        deliver_to=tmp_path / "out",
    )

    assert isinstance(decision, Decision)
    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"
