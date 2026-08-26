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
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from attest import cli, issue, keys, pq, revocation, ulid
from demo import custodian as custodian_mod
from demo.custodian import Custodian, Decision
from demo.pledge_dies import run_demo

CapSys = pytest.CaptureFixture[str]

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
    pub_seed: Path
    pub_mldsa: Path
    store_seed: Path
    store_mldsa: Path
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
        pub_seed=pub_seed,
        pub_mldsa=pub_mldsa,
        store_seed=store_seed,
        store_mldsa=store_mldsa,
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


def _receipt_id_of(receipt: Path) -> str:
    envelope = json.loads(receipt.read_text(encoding="utf-8"))
    return str(envelope["payload"]["receipt_id"])


def _gate(world: World, home: Path, **overrides: Any) -> Custodian:
    """A custodian whose challenge bookkeeping lives under `home`.

    Every gate in this file gets a directory of its own: the challenges a
    custodian has minted and not yet spent are its own state, and two gates
    sharing that state would be one gate wearing two hats.
    """
    kwargs: dict[str, Any] = {
        "audience": ARCHIVE,
        "archive_dir": world.archive_dir,
        "trust_dir": world.trust_dir,
        "challenge_dir": home / "challenges",
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


def _artifact_entry(filename: str, data: bytes) -> dict[str, Any]:
    return {
        "role": "installer",
        "platform": "linux-x86_64",
        "filename": filename,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _series_grant_view(world: World, tmp_path: Path) -> tuple[Path, str]:
    grant_path = tmp_path / "series-grant.json"
    grant_report = _cli(
        [
            "grant",
            "issue",
            "--grant-version",
            "1",
            "--publisher",
            PUBLISHER,
            "--artifact-series",
            SERIES,
            "--permission",
            "deliver-to-holder",
            "--mode",
            "publisher-declaration",
            "--legal-text-uri",
            f"https://{PUBLISHER}/pledge/series-grant-v1.json",
            "--legal-text-sha256",
            hashlib.sha256(LEGAL_BYTES).hexdigest(),
            "--jurisdiction",
            "IT",
            "--issued-at",
            EPOCH,
            "--seed",
            str(world.pub_seed),
            "--kid",
            PUB_KID,
            "--mldsa-seed",
            str(world.pub_mldsa),
            "--out",
            str(grant_path),
        ]
    )
    declaration_path = tmp_path / "series-declaration.json"
    _cli(
        [
            "grant",
            "declare",
            "--publisher",
            PUBLISHER,
            "--artifact-series",
            SERIES,
            "--declared-at",
            "2027-01-01T00:00:00Z",
            "--seed",
            str(world.pub_seed),
            "--kid",
            PUB_KID,
            "--mldsa-seed",
            str(world.pub_mldsa),
            "--out",
            str(declaration_path),
        ]
    )
    view = tmp_path / "series-grant-view-active.json"
    view.write_text(
        json.dumps(
            {
                "grant": json.loads(grant_path.read_text(encoding="utf-8")),
                "declarations": [json.loads(declaration_path.read_text(encoding="utf-8"))],
            }
        ),
        encoding="utf-8",
    )
    return view, str(grant_report["grant_sha256"])


def _signed_receipt_for_artifact(
    world: World,
    tmp_path: Path,
    *,
    filename: str,
    data: bytes,
    grant_sha256: str,
    receipt_id: str,
) -> Path:
    buyer_pub = keys.from_seed(
        keys.b64u_decode(world.buyer_seed.read_text(encoding="utf-8").strip())
    ).pub
    payload = issue.build_payload(
        issuer_id=STORE,
        display_name="The Store That Pledged",
        buyer_identifier="casey@example.com",
        buyer_identifier_type="email",
        buyer_salt=keys.b64u_decode(world.salt_b64u),
        buyer_pubkey=buyer_pub,
        title="Pledged Game",
        publisher="Indie Games Co-op",
        identifiers={"issuer_sku": "PLEDGE-001"},
        artifact_series=SERIES,
        terms_uri=f"https://{STORE}/attest/license-templates/standard-v1",
        legal_text_sha256=hashlib.sha256(LEGAL_BYTES).hexdigest(),
        artifacts=[_artifact_entry(filename, data)],
        revocability="none",
        drm="drm-free",
        end_of_life="sunset-grant",
        eol_commitment_uri=f"https://{PUBLISHER}/pledge/series-grant-v1.json",
        eol_commitment_sha256=grant_sha256,
        publisher_id=PUBLISHER,
        preservation_pledge={
            "pledge": "sunset-grant-v1",
            "grant_uri": f"https://{PUBLISHER}/pledge/series-grant-v1.json",
            "grant_sha256": grant_sha256,
        },
        issued_at=EPOCH,
        receipt_id=receipt_id,
        attest_version="0.2",
    )
    slug = filename.replace(".", "-")
    payload_path = tmp_path / f"payload-{slug}.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    salt_path = tmp_path / f"receipt-{slug}.salt"
    salt_path.write_text(world.salt_b64u, encoding="utf-8")
    receipt = tmp_path / f"receipt-{slug}.attest.json"
    _cli(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(world.store_seed),
            "--kid",
            STORE_KID,
            "--salt",
            str(salt_path),
            "--attest-version",
            "0.2",
            "--mldsa-key",
            str(world.store_mldsa),
            "--out",
            str(receipt),
        ]
    )
    return receipt


def _signed_receipt_with_filename(world: World, tmp_path: Path, filename: str) -> Path:
    payload = json.loads(world.receipt.read_text(encoding="utf-8"))["payload"]
    payload = json.loads(json.dumps(payload))
    payload["work"]["artifacts"][0]["filename"] = filename

    payload_path = tmp_path / "payload-with-hostile-filename.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    salt_path = tmp_path / "receipt.salt"
    salt_path.write_text(world.salt_b64u, encoding="utf-8")
    receipt = tmp_path / "receipt-with-hostile-filename.attest.json"
    _cli(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(world.store_seed),
            "--kid",
            STORE_KID,
            "--salt",
            str(salt_path),
            "--attest-version",
            "0.2",
            "--mldsa-key",
            str(world.store_mldsa),
            "--out",
            str(receipt),
        ]
    )
    return receipt


def _transferred_feed(world: World, tmp_path: Path) -> Path:
    """A revocation feed carrying one issuer-signed `transferred` record for
    the world's receipt — the only party who can produce one."""
    mldsa_obj = json.loads(world.store_mldsa.read_text())
    signer = pq.HybridSigningKeys(
        ed=keys.from_seed(keys.b64u_decode(world.store_seed.read_text().strip())),
        mldsa=pq.MLDSAKeyPair(
            sk=keys.b64u_decode(mldsa_obj["sk"]), pub=keys.b64u_decode(mldsa_obj["pub"])
        ),
    )
    receipt_id = json.loads(world.receipt.read_text())["payload"]["receipt_id"]
    record = revocation.build_record(
        receipt_id, "transferred", "2027-06-01T00:00:00Z", signer, STORE_KID
    )
    feed = tmp_path / "transferred-feed.json"
    feed.write_text(json.dumps([record]), encoding="utf-8")
    return feed


# --------------------------------------------------------------------------
# The one case that must succeed — without it the refusals prove nothing.
# --------------------------------------------------------------------------


def test_a_valid_redemption_is_served(world: World, tmp_path: Path) -> None:
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is True
    assert decision.reason == "served"
    assert decision.delivered is not None
    assert decision.delivered.read_bytes() == WORK_BYTES


def test_redeem_freezes_the_receipt_before_artifact_selection(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grant_view, grant_sha256 = _series_grant_view(world, tmp_path)
    archive = tmp_path / "archive"
    archive.mkdir()
    first_bytes = b"first receipt artifact\n"
    second_bytes = b"second receipt artifact\n"
    (archive / "first.bin").write_bytes(first_bytes)
    (archive / "second.bin").write_bytes(second_bytes)
    first_receipt = _signed_receipt_for_artifact(
        world,
        tmp_path,
        filename="first.bin",
        data=first_bytes,
        grant_sha256=grant_sha256,
        receipt_id="01ARZ3NDEKTSV4RRFFQ69G5FA1",
    )
    second_receipt = _signed_receipt_for_artifact(
        world,
        tmp_path,
        filename="second.bin",
        data=second_bytes,
        grant_sha256=grant_sha256,
        receipt_id="01ARZ3NDEKTSV4RRFFQ69G5FA2",
    )
    request_receipt = tmp_path / "request.attest.json"
    request_receipt.write_bytes(first_receipt.read_bytes())

    gate = _gate(world, tmp_path, archive_dir=archive)
    challenge = gate.challenge(receipt=request_receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    original_run_cli = custodian_mod._driver.run_cli
    swapped = False

    def swap_after_redemption_verify(argv: list[str]) -> tuple[int, str, str]:
        nonlocal swapped
        result = original_run_cli(argv)
        if argv[:2] == ["grant", "verify"] and not swapped:
            request_receipt.write_bytes(second_receipt.read_bytes())
            swapped = True
        return result

    monkeypatch.setattr(custodian_mod._driver, "run_cli", swap_after_redemption_verify)

    decision = gate.redeem(
        receipt=request_receipt,
        grant_view=grant_view,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert swapped is True
    assert decision.served is True
    assert decision.delivered is not None
    assert decision.delivered.name == "first.bin"
    assert decision.delivered.read_bytes() == first_bytes
    assert not (tmp_path / "out" / "second.bin").exists()


# --------------------------------------------------------------------------
# The refusal matrix, one reason per test.
# --------------------------------------------------------------------------


def test_the_salt_is_refused_as_a_redemption_proof(world: World, tmp_path: Path) -> None:
    """§18.7 forbids the buyer-binding salt as a redemption proof. The gate
    must refuse it even when everything else about the request is valid —
    that is what makes it a prohibition rather than a fallback."""
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
        offered_salt=world.salt_b64u,
    )

    assert decision.served is False
    assert decision.reason == "salt_disclosure_rejected"
    # Refused before the proof step, so nothing was spent: the challenge this
    # holder legitimately asked for is still theirs to answer properly.
    assert challenge.is_file()


def test_a_dormant_grant_is_refused(world: World, tmp_path: Path) -> None:
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_dormant,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "grant_not_activated"
    assert challenge.is_file()


def test_a_tampered_receipt_is_refused(world: World, tmp_path: Path) -> None:
    tampered = tmp_path / "tampered.attest.json"
    envelope = json.loads(world.receipt.read_text())
    envelope["payload"]["work"]["title"] = "Something Else Entirely"
    tampered.write_text(json.dumps(envelope), encoding="utf-8")

    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=tampered,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "receipt_not_ok"
    # The tampered envelope names the same receipt_id, so it could have
    # reached for the outstanding challenge — it never gets that far.
    assert challenge.is_file()


def test_a_revoked_receipt_is_refused(world: World, tmp_path: Path) -> None:
    """An archive gate that never consults revocation is a weaker gate: the
    receipt still verifies, and the grant is still activated, but the deal it
    records has been undone."""
    gate = _gate(world, tmp_path, revocations=world.revocable_revocations)
    challenge = gate.challenge(receipt=world.revocable_receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.revocable_receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "revocation_blocked"
    assert challenge.is_file()


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
    gate = _gate(world, tmp_path, revocations=world.revocations)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is True
    assert decision.reason == "served"


def test_a_transferred_receipt_is_refused(world: World, tmp_path: Path) -> None:
    """The other side of the coin from the bogus record above.

    A record saying this receipt was TRANSFERRED, signed by the issuer's own
    key and naming this very receipt_id, makes the verifier warn
    `transferred_revocation_unbacked` — it has no transfer view to resolve
    the claim against. Only the issuer can produce that warning for this
    receipt, so unlike the generic ignored-record state it is not a lever a
    passer-by can pull, and the gate reads it: whoever is owed the copy, it
    is no longer certainly the party in front of it.
    """
    gate = _gate(world, tmp_path, revocations=_transferred_feed(world, tmp_path))
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "revocation_blocked"
    assert "transferred" in decision.detail


def test_a_proof_signed_by_a_foreign_key_is_refused(world: World, tmp_path: Path) -> None:
    """The attacker holds the PUBLIC bundle but not the buyer's seed."""
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "forged.json", seed=world.foreign_seed)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"


def test_a_proof_minted_for_another_custodian_is_refused(world: World, tmp_path: Path) -> None:
    """The audience is inside the signed preimage, so a response the holder
    legitimately produced for one archive cannot be replayed at another."""
    elsewhere = _gate(world, tmp_path / "elsewhere", audience=OTHER_ARCHIVE)
    other_challenge = elsewhere.challenge(receipt=world.receipt)
    replayed = _respond(world, other_challenge, tmp_path / "replayed.json")

    gate = _gate(world, tmp_path)
    gate.challenge(receipt=world.receipt)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=replayed,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"


def test_a_response_to_another_custodians_challenge_is_refused(
    world: World, tmp_path: Path
) -> None:
    """A requester cannot bring an answer from somebody else's transcript.

    The twin here shares this gate's AUDIENCE, so the audience binding is
    deliberately not what does the work: the two custodians differ only in
    which challenge each is holding. The response answers the twin's nonce,
    this gate spends its own, and the signature does not match it.
    """
    twin = _gate(world, tmp_path / "twin")
    twin_challenge = twin.challenge(receipt=world.receipt)
    twin_response = _respond(world, twin_challenge, tmp_path / "twin-response.json")

    gate = _gate(world, tmp_path)
    gate.challenge(receipt=world.receipt)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=twin_response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"


def test_a_replayed_response_is_refused(world: World, tmp_path: Path) -> None:
    """The reason the custodian owns its challenges: a response is good once.

    The first request is the legitimate one and succeeds. Presenting the very
    same response again — the transcript an eavesdropper, a shared machine or
    a backup would hand an attacker — finds nothing left to answer, because
    the challenge was spent by being used.
    """
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    first = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )
    assert first.served is True
    assert not challenge.exists()

    replayed = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out-again",
    )

    assert replayed.served is False
    assert replayed.reason == "redemption_proof_invalid"
    assert replayed.delivered is None


def test_a_failed_redemption_also_spends_the_challenge(world: World, tmp_path: Path) -> None:
    """Consumption is by USE, not by success.

    A challenge that survived a failed attempt would be an oracle: an
    attacker could grind responses against one nonce for as long as they
    liked. The holder's cost is a round trip; the attacker's is a fresh
    challenge they cannot obtain without the receipt.
    """
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    forged = _respond(world, challenge, tmp_path / "forged.json", seed=world.foreign_seed)
    honest = _respond(world, challenge, tmp_path / "honest.json")

    assert (
        gate.redeem(
            receipt=world.receipt,
            grant_view=world.grant_view_active,
            response=forged,
            deliver_to=tmp_path / "out",
        ).reason
        == "redemption_proof_invalid"
    )
    assert not challenge.exists()

    # The right answer to a spent challenge is no longer an answer at all.
    after = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=honest,
        deliver_to=tmp_path / "out",
    )

    assert after.served is False
    assert after.reason == "redemption_proof_invalid"


def test_challenge_claim_does_not_unlink_a_fresh_mint(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    original_read_bytes = Path.read_bytes
    original_run_cli = custodian_mod._driver.run_cli
    minted_during_old_read = False
    fresh_challenge: Path | None = None

    def remint_after_old_read(path: Path) -> bytes:
        nonlocal fresh_challenge, minted_during_old_read
        data = original_read_bytes(path)
        if path == challenge and fresh_challenge is None:
            fresh_challenge = gate.challenge(receipt=world.receipt)
            minted_during_old_read = True
        return data

    def remint_after_atomic_claim(argv: list[str]) -> tuple[int, str, str]:
        nonlocal fresh_challenge
        if (
            argv[:2] == ["grant", "verify"]
            and fresh_challenge is None
            and not minted_during_old_read
        ):
            fresh_challenge = gate.challenge(receipt=world.receipt)
        return original_run_cli(argv)

    monkeypatch.setattr(Path, "read_bytes", remint_after_old_read)
    monkeypatch.setattr(custodian_mod._driver, "run_cli", remint_after_atomic_claim)

    first = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert first.served is True
    assert fresh_challenge is not None
    assert fresh_challenge.exists()

    fresh_response = _respond(world, fresh_challenge, tmp_path / "fresh-response.json")
    second = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=fresh_response,
        deliver_to=tmp_path / "out-again",
    )

    assert second.served is True
    assert second.delivered is not None
    assert second.delivered.read_bytes() == WORK_BYTES


def test_a_request_answering_no_outstanding_challenge_is_refused(
    world: World, tmp_path: Path
) -> None:
    """The defect this redesign closes, stated directly.

    The requester writes their own challenge document — this custodian's
    audience, this receipt's id, a nonce of their choosing — and signs a
    perfectly well-formed response to it. There is nowhere left to hand it
    in: `redeem` reads the challenge from the custodian's own directory, and
    nothing was ever minted there for this receipt.
    """
    self_dealt = tmp_path / "self-dealt-challenge.json"
    self_dealt.write_text(
        json.dumps(
            {
                "receipt_id": json.loads(world.receipt.read_text())["payload"]["receipt_id"],
                "audience": ARCHIVE,
                "nonce": keys.b64u(os.urandom(32)),
            }
        ),
        encoding="utf-8",
    )
    response = _respond(world, self_dealt, tmp_path / "self-dealt-response.json")

    gate = _gate(world, tmp_path)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
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

    gate = _gate(world, tmp_path, archive_dir=drifted)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "artifact_out_of_scope"


def test_an_archive_copy_named_by_absolute_receipt_path_is_refused(
    world: World, tmp_path: Path
) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / FILENAME
    outside_file.write_bytes(WORK_BYTES)
    receipt = _signed_receipt_with_filename(world, tmp_path, str(outside_file))

    gate = _gate(world, tmp_path, archive_dir=archive)
    challenge = gate.challenge(receipt=receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "artifact_out_of_scope"


def test_an_archive_copy_named_by_parent_traversal_is_refused(world: World, tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / FILENAME
    outside_file.write_bytes(WORK_BYTES)
    receipt = _signed_receipt_with_filename(world, tmp_path, f"../outside/{FILENAME}")

    gate = _gate(world, tmp_path, archive_dir=archive)
    challenge = gate.challenge(receipt=receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "artifact_out_of_scope"


def test_an_archive_copy_named_with_a_nul_byte_is_refused(world: World, tmp_path: Path) -> None:
    """A filename the filesystem cannot even be asked about.

    A NUL byte passes the receipt schema (`minLength: 1` and nothing more)
    and is signed into the payload like any other name, but resolving it
    raises `ValueError` rather than answering. A candidate that cannot be
    named is out of the running exactly like one that is missing — and the
    request gets a verdict, not a traceback.
    """
    receipt = _signed_receipt_with_filename(world, tmp_path, "pledged\x00game.bin")

    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=receipt)
    response = _respond(world, challenge, tmp_path / "response.json")

    decision = gate.redeem(
        receipt=receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert isinstance(decision, Decision)
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
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    seed = world.foreign_seed if case == "foreign_key" else None
    response = _respond(world, challenge, tmp_path / "response.json", seed=seed)
    deliver_to = tmp_path / "out"

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_dormant if case == "dormant" else world.grant_view_active,
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
    gate = _gate(world, tmp_path)
    challenge = gate.challenge(receipt=world.receipt)
    response = _respond(world, challenge, tmp_path / "response.json")
    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )
    assert decision.reason in custodian_mod.REASONS


def test_the_revocation_vocabulary_covers_transfer_as_well_as_revocation() -> None:
    """A transferred receipt remains a refusal value for a future verdict.

    Today's CLI has no transfer-view flag, so the `revocation` member itself
    cannot read `transferred`; the constant pins how the gate would treat it
    if a verifier reported it. The transfer the gate CAN see today arrives as
    a warning instead, and that name is pinned here too, because a warning
    string is the whole load-bearing evidence of that refusal.
    """
    assert custodian_mod.REVOCATION_REFUSED == frozenset({"revoked", "transferred"})
    assert custodian_mod.TRANSFERRED_UNBACKED == "transferred_revocation_unbacked"


def test_a_hostile_request_never_raises(world: World, tmp_path: Path) -> None:
    """Every refusal is a verdict, never an exception: a gate that raises on
    hostile input leaks which check failed through the shape of the crash."""
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json at all", encoding="utf-8")

    gate = _gate(world, tmp_path)
    gate.challenge(receipt=world.receipt)

    decision = gate.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=garbage,
        deliver_to=tmp_path / "out",
    )

    assert isinstance(decision, Decision)
    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"


# --------------------------------------------------------------------------
# The demo itself: `demo/pledge_dies.py`, publisher-declaration pass.
# --------------------------------------------------------------------------


def test_the_pledge_fires_and_the_gate_delivers(tmp_path: Path, capsys: CapSys) -> None:
    outcomes = run_demo(tmp_path)
    narration = capsys.readouterr().out

    assert outcomes["trigger"] == "publisher-declaration"
    assert outcomes["receipt_id"]

    # The store is gone before anything is asked of the gate.
    assert outcomes["store_dir_deleted"] is True
    assert not (tmp_path / "store").exists()

    # Dormant first: the pledge exists, the trigger has not fired.
    assert outcomes["verify_dormant"]["ok"] is True
    assert outcomes["verify_dormant"]["grant"] == "dormant"
    assert outcomes["refusal_dormant"] == "grant_not_activated"

    # Then the rights holder declares, and only then does the grant activate.
    assert outcomes["verify_activated"]["grant"] == "activated"

    # The refusals that matter, at an ACTIVE grant.
    assert outcomes["refusal_bad_receipt"] == "receipt_not_ok"
    assert outcomes["refusal_bad_proof"] == "redemption_proof_invalid"
    assert outcomes["refusal_replayed_proof"] == "redemption_proof_invalid"
    assert outcomes["refusal_salt"] == "salt_disclosure_rejected"

    # And the delivery, checked against the receipt that outlived the store.
    assert outcomes["served"] == "served"
    assert outcomes["check_artifact"]["match"] is True
    assert outcomes["check_artifact_exit_code"] == 0

    delivered = Path(outcomes["delivered"])
    assert delivered.is_file()
    assert delivered.read_bytes() == Path(outcomes["archived_copy"]).read_bytes()

    for step in ("Step 6", "Step 8", "Step 9", "Step 11"):
        assert step in narration


def test_the_gate_refuses_before_the_declaration_exists(tmp_path: Path) -> None:
    """The anti-overclaim guard: the demo must not mint the declaration and
    then narrate a refusal it never really faced. The dormant refusal is
    recorded while the declaration file does not yet exist on disk."""
    outcomes = run_demo(tmp_path)

    assert outcomes["declaration_existed_at_dormant_refusal"] is False
    assert outcomes["refusal_dormant"] == "grant_not_activated"


def test_the_buyer_secrets_are_owner_only(tmp_path: Path) -> None:
    """Two secrets now, not one: the binding salt and the buyer's own signing
    seed. Losing the seed is losing the ability to redeem at all."""
    outcomes = run_demo(tmp_path)

    for key in ("salt_path", "buyer_seed_path"):
        mode = stat.S_IMODE(Path(outcomes[key]).stat().st_mode)
        assert mode == 0o600, f"{key} is {oct(mode)}, expected 0o600"


def test_the_demo_touches_nothing_outside_its_own_workspace(tmp_path: Path) -> None:
    """The demo deletes a directory. The guard is not that it deletes the
    right one, it is that it cannot reach past its own workspace."""
    canary_root = tmp_path / "canary"
    canary_root.mkdir()
    canary = canary_root / "do-not-touch.txt"
    canary.write_text("untouched", encoding="utf-8")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_demo(workspace)

    assert canary.read_text(encoding="utf-8") == "untouched"


# --------------------------------------------------------------------------
# The same sequence, with the backstop instead of the declaration.
# --------------------------------------------------------------------------


def test_the_fixed_date_backstop_delivers_with_nobody_left_to_declare(
    tmp_path: Path,
) -> None:
    """The second trigger exists for the case the first cannot cover: the
    rights holder is gone too, and nobody is left to sign anything. Time
    itself becomes the trigger, proved by an anchor rather than asserted."""
    outcomes = run_demo(tmp_path, trigger="fixed-date")

    assert outcomes["trigger"] == "fixed-date"
    assert outcomes["declaration_minted"] is False

    assert outcomes["verify_dormant"]["grant"] == "dormant"
    assert outcomes["refusal_dormant"] == "grant_not_activated"
    assert outcomes["verify_activated"]["grant"] == "activated"

    assert outcomes["served"] == "served"
    assert outcomes["check_artifact"]["match"] is True


def test_the_backstop_stays_shut_until_the_pinned_header_passes_the_date(
    tmp_path: Path,
) -> None:
    """The half that actually proves something: with the SAME grant and the
    same kind of evidence, an anchor whose header predates the backstop leaves
    the grant closed. Without this, "activated" would only show that passing
    any bundle at all is enough."""
    outcomes = run_demo(tmp_path, trigger="fixed-date")

    assert outcomes["anchor_before_the_date"]["grant"] == "dormant"
    assert outcomes["anchor_after_the_date"]["grant"] == "activated"


def test_an_unknown_trigger_is_refused_rather_than_guessed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported trigger"):
        run_demo(tmp_path, trigger="heartbeat-absence")


# --------------------------------------------------------------------------
# Defence in depth: what happens when the custodian's own storage is shared.
# --------------------------------------------------------------------------


def test_an_answer_to_a_neighbours_challenge_in_a_shared_directory_is_refused(
    world: World, tmp_path: Path
) -> None:
    """Owning the challenge is the gate's primitive, and a shared directory
    quietly takes it away: two custodians keyed by the same `receipt_id`
    read each other's file. The audience is re-checked on the way out for
    exactly this reason — a one-line defence that costs nothing when the
    directory is private and restores §18.7's binding when it is not."""
    shared = tmp_path / "shared-challenges"
    ours = _gate(world, tmp_path, challenge_dir=shared)
    neighbour = _gate(world, tmp_path, audience=OTHER_ARCHIVE, challenge_dir=shared)

    # The neighbour mints; the holder answers the neighbour, legitimately.
    neighbour.challenge(receipt=world.receipt)
    response = _respond(
        world, shared / f"{_receipt_id_of(world.receipt)}.json", tmp_path / "response.json"
    )

    decision = ours.redeem(
        receipt=world.receipt,
        grant_view=world.grant_view_active,
        response=response,
        deliver_to=tmp_path / "out",
    )

    assert decision.served is False
    assert decision.reason == "redemption_proof_invalid"


def test_an_unreadable_archive_copy_is_a_verdict_not_a_crash(world: World, tmp_path: Path) -> None:
    """The archive's own storage is environment, not requester input — but
    the module's invariant is absolute: refusals are verdicts, never
    exceptions. A copy the process cannot read leaves the running like one
    that is missing."""
    archive = tmp_path / "unreadable-archive"
    archive.mkdir()
    blocked = archive / FILENAME
    blocked.write_bytes(WORK_BYTES)
    blocked.chmod(0o000)

    gate = _gate(world, tmp_path, archive_dir=archive)
    gate.challenge(receipt=world.receipt)
    response = _respond(
        world,
        gate.challenge_dir / f"{_receipt_id_of(world.receipt)}.json",
        tmp_path / "response.json",
    )
    try:
        decision = gate.redeem(
            receipt=world.receipt,
            grant_view=world.grant_view_active,
            response=response,
            deliver_to=tmp_path / "out",
        )
    finally:
        blocked.chmod(0o600)

    assert decision.served is False
    assert decision.reason == "artifact_out_of_scope"
