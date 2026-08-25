"""Tests for the `grant` CLI group and `verify --grant-view` (v0.2 §18).

Five verbs across three parties: `issue`/`declare` are the RIGHTS HOLDER's,
`challenge`/`verify` are the CUSTODIAN's, `respond` is the HOLDER's. The
end-to-end test walks the whole Appendix A exchange through the CLI itself —
pledge signed at issuance, store dies, cessation declared, grant activated,
redemption challenged, answered and checked — because that sequence is the
thing V-D.2's demo has to be able to run from a shell, and a group of verbs
that each work alone but do not compose is not a usable surface.

`cli.main([...])` is driven directly (no subprocess), the idiom
`tests/test_cli.py` established.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attest import cli, grant, keys
from tests.helpers import make_payload

ISSUER = "store.example.com"
PUBLISHER = "pub.example"
SUCCESSOR = "heritage.example"
CUSTODIAN = "archive.example"

ISSUER_KID = f"{ISSUER}/keys/test-1#ed25519-1"
PUB_KID = f"{PUBLISHER}/keys/grants-1#ed25519-1"
SUCCESSOR_KID = f"{SUCCESSOR}/keys/grants-1#ed25519-1"

VALID_FROM = "2026-01-01T00:00:00Z"
GRANT_ISSUED_AT = "2026-02-01T00:00:00Z"
DECLARED_AT = "2031-03-01T00:00:00Z"

RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-test-sunset-grant-prose-v1").hexdigest()

CapSys = pytest.CaptureFixture[str]


# --- helpers -----------------------------------------------------------------


def _keygen_hybrid(tmp_path: Path, name: str) -> tuple[Path, Path, Path]:
    seed, pub, mldsa = (
        tmp_path / f"{name}.seed",
        tmp_path / f"{name}.pub",
        tmp_path / f"{name}.mldsa",
    )
    assert (
        cli.main(
            [
                "keygen",
                "--seed-out",
                str(seed),
                "--pub-out",
                str(pub),
                "--hybrid",
                "--mldsa-out",
                str(mldsa),
            ]
        )
        == 0
    )
    return seed, pub, mldsa


def _manifest(tmp_path: Path, issuer: str, kid: str, seed: Path, mldsa: Path, name: str) -> Path:
    out = tmp_path / name
    assert (
        cli.main(
            [
                "manifest",
                "init",
                "--issuer",
                issuer,
                "--kid",
                kid,
                "--seed",
                str(seed),
                "--mldsa-key",
                str(mldsa),
                "--valid-from",
                VALID_FROM,
                "--issued-at",
                VALID_FROM,
                "--out",
                str(out),
            ]
        )
        == 0
    )
    return out


def _last_json(capsys: CapSys) -> dict[str, Any]:
    """The LAST report the CLI printed. `_print_json` pretty-prints, so a
    report spans many lines and several commands may have run since the last
    read — the last line that is a bare `{` is where the final object starts."""
    lines = capsys.readouterr().out.rstrip().splitlines()
    start = max(i for i, line in enumerate(lines) if line == "{")
    parsed = json.loads("\n".join(lines[start:]))
    assert isinstance(parsed, dict)
    return parsed


def _grant_issue_argv(
    seed: Path, mldsa: Path, out: Path, *extra: str, kid: str = PUB_KID
) -> list[str]:
    return [
        "grant",
        "issue",
        "--grant-version",
        "1",
        "--publisher",
        PUBLISHER,
        "--artifact",
        RECEIPT_ART,
        "--legal-text-uri",
        "https://pub.example/sunset-grant-v1",
        "--legal-text-sha256",
        LEGAL_TEXT_SHA256,
        "--jurisdiction",
        "IT",
        "--issued-at",
        GRANT_ISSUED_AT,
        "--seed",
        str(seed),
        "--mldsa-seed",
        str(mldsa),
        "--kid",
        kid,
        "--out",
        str(out),
        *extra,
    ]


def _world(tmp_path: Path, capsys: CapSys) -> dict[str, Any]:
    """One issuer, one publisher, one successor, a trust dir holding all three
    manifests, and a signed grant — the shared world every test below mutates
    exactly one thing in."""
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()

    issuer_seed, _, issuer_mldsa = _keygen_hybrid(tmp_path, "issuer")
    pub_seed, _, pub_mldsa = _keygen_hybrid(tmp_path, "publisher")
    successor_seed, _, successor_mldsa = _keygen_hybrid(tmp_path, "successor")
    buyer_seed, buyer_pub, _ = _keygen_hybrid(tmp_path, "buyer")

    _manifest(trust_dir, ISSUER, ISSUER_KID, issuer_seed, issuer_mldsa, "issuer.json")
    _manifest(trust_dir, PUBLISHER, PUB_KID, pub_seed, pub_mldsa, "publisher.json")
    _manifest(trust_dir, SUCCESSOR, SUCCESSOR_KID, successor_seed, successor_mldsa, "heritage.json")

    grant_path = tmp_path / "grant.json"
    assert cli.main(_grant_issue_argv(pub_seed, pub_mldsa, grant_path)) == 0
    grant_sha256 = _last_json(capsys)["grant_sha256"]

    payload = make_payload(
        attest_version="0.2",
        issuer={"id": ISSUER, "display_name": "Example Store"},
        buyer={"pubkey": buyer_pub.read_text(encoding="utf-8").strip()},
        work={"publisher_id": PUBLISHER},
        license={
            "preservation_pledge": {
                "pledge": "sunset-grant-v1",
                "grant_uri": "https://pub.example/sunset-grant-v1.json",
                "grant_sha256": grant_sha256,
            }
        },
        survivability={"end_of_life": "sunset-grant"},
    )
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    receipt = tmp_path / "receipt.json"
    assert (
        cli.main(
            [
                "issue",
                "--payload",
                str(payload_path),
                "--attest-version",
                "0.2",
                "--seed",
                str(issuer_seed),
                "--mldsa-key",
                str(issuer_mldsa),
                "--kid",
                ISSUER_KID,
                "--out",
                str(receipt),
            ]
        )
        == 0
    )
    capsys.readouterr()

    return {
        "tmp": tmp_path,
        "trust_dir": trust_dir,
        "receipt": receipt,
        "grant": grant_path,
        "grant_sha256": grant_sha256,
        "pub_seed": pub_seed,
        "pub_mldsa": pub_mldsa,
        "successor_seed": successor_seed,
        "successor_mldsa": successor_mldsa,
        "buyer_seed": buyer_seed,
    }


def _write_view(tmp_path: Path, **members: Any) -> Path:
    path = tmp_path / "grant-view.json"
    path.write_text(json.dumps(members), encoding="utf-8")
    return path


def _declare(
    world: dict[str, Any],
    out_name: str = "declaration.json",
    *,
    seed_key: str = "pub_seed",
    mldsa_key: str = "pub_mldsa",
    kid: str = PUB_KID,
) -> Path:
    out = world["tmp"] / out_name
    assert (
        cli.main(
            [
                "grant",
                "declare",
                "--publisher",
                PUBLISHER,
                "--artifact",
                RECEIPT_ART,
                "--declared-at",
                DECLARED_AT,
                "--seed",
                str(world[seed_key]),
                "--mldsa-seed",
                str(world[mldsa_key]),
                "--kid",
                kid,
                "--out",
                str(out),
            ]
        )
        == 0
    )
    return out


# --- grant issue -------------------------------------------------------------


def test_grant_issue_writes_a_document_that_authenticates_and_reports_its_hash(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    """The reported hash is the point: it is what goes into the receipt's
    `license.preservation_pledge.grant_sha256`, and an operator recomputing it
    by hand from a canonicalization they have to get right is how a grant ends
    up unbindable to the receipt meant to carry it."""
    document = json.loads(world["grant"].read_text(encoding="utf-8"))

    assert set(document) == {
        "grant_version",
        "publisher",
        "scope",
        "permissions",
        "activation",
        "unprotected_build",
        "legal_text_uri",
        "legal_text_sha256",
        "jurisdiction",
        "issued_at",
        "signature",
    }
    assert grant.grant_hash(document) == world["grant_sha256"]
    assert document["permissions"] == ["deliver-to-holder"]
    assert document["activation"]["modes"] == ["publisher-declaration"]
    assert document["unprotected_build"] is True


def test_grant_issue_sorts_and_deduplicates_the_scope(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    """The order is normative, and a tool that silently signs an unsorted array
    produces a document a conforming verifier rejects for a reason the operator
    cannot see."""
    other = hashlib.sha256(b"artifact-elsewhere").hexdigest()
    out = world["tmp"] / "sorted.json"
    argv = _grant_issue_argv(
        world["pub_seed"], world["pub_mldsa"], out, "--artifact", other, "--artifact", RECEIPT_ART
    )

    assert cli.main(argv) == 0

    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["scope"]["artifacts"] == sorted({RECEIPT_ART, other})


def test_grant_issue_refuses_a_fixed_date_whose_mode_was_never_declared(
    tmp_path: Path, capsys: CapSys
) -> None:
    """§18.2: a non-null `fixed_date` REQUIRES "fixed-date" in `modes`. Refusing
    beats adding the mode silently — the operator is signing a trigger, and a
    tool that widens one on their behalf is signing something else."""
    world = _world(tmp_path, capsys)
    out = world["tmp"] / "bad.json"
    argv = _grant_issue_argv(
        world["pub_seed"], world["pub_mldsa"], out, "--fixed-date", "2046-01-01T00:00:00Z"
    )

    assert cli.main(argv) == 2
    assert not out.exists()


def test_grant_issue_requires_a_scope(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    out = world["tmp"] / "scopeless.json"
    argv = [a for a in _grant_issue_argv(world["pub_seed"], world["pub_mldsa"], out)]
    del argv[argv.index("--artifact") : argv.index("--artifact") + 2]

    assert cli.main(argv) == 2


def test_grant_issue_rejects_a_malformed_artifact_hash(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    out = world["tmp"] / "bad-hash.json"
    argv = _grant_issue_argv(world["pub_seed"], world["pub_mldsa"], out, "--artifact", "NOTAHASH")

    assert cli.main(argv) == 2


def test_grant_issue_refuses_to_clobber_its_own_signing_key(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    argv = _grant_issue_argv(world["pub_seed"], world["pub_mldsa"], world["pub_seed"])

    assert cli.main(argv) == 2


# --- grant declare -----------------------------------------------------------


def test_grant_declare_writes_a_four_member_declaration(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    path = _declare(world)
    reported = _last_json(capsys)

    declaration = json.loads(path.read_text(encoding="utf-8"))
    assert set(declaration) == {"publisher", "scope", "declared_at", "signature"}
    assert reported["declaration_sha256"] == grant.declaration_hash(declaration)


# --- verify --grant-view -----------------------------------------------------


def test_verify_without_grant_view_reports_the_pre_stage_4_defaults(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    rc = cli.main(["verify", str(world["receipt"]), "--trust-dir", str(world["trust_dir"])])
    report = _last_json(capsys)

    assert rc == 0
    assert report["ok"] is True
    assert report["grant"] == "not_checked"
    assert report["grant_trust"] == "not_checked"


def test_verify_with_a_grant_view_but_no_trigger_reports_dormant(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    view = _write_view(world["tmp"], grant=json.loads(world["grant"].read_text(encoding="utf-8")))

    rc = cli.main(
        [
            "verify",
            str(world["receipt"]),
            "--trust-dir",
            str(world["trust_dir"]),
            "--grant-view",
            str(view),
        ]
    )
    report = _last_json(capsys)

    assert rc == 0
    assert report["grant"] == "dormant"
    # A --trust-dir is bundle provenance by construction (design §5): a manifest
    # dropped in a directory carries no domain-control evidence, so the publisher
    # ladder tops out at TOFU exactly as the issuer's does.
    assert report["grant_trust"] == "unauthenticated_tofu"
    assert report["trust"] == "unauthenticated_tofu"


def test_a_declaration_opens_the_grant_through_the_cli(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    declaration = _declare(world)
    capsys.readouterr()
    view = _write_view(
        world["tmp"],
        grant=json.loads(world["grant"].read_text(encoding="utf-8")),
        declarations=[json.loads(declaration.read_text(encoding="utf-8"))],
    )

    rc = cli.main(
        [
            "verify",
            str(world["receipt"]),
            "--trust-dir",
            str(world["trust_dir"]),
            "--grant-view",
            str(view),
        ]
    )
    report = _last_json(capsys)

    assert rc == 0
    assert report["grant"] == "activated"
    # D6: the grant never touches `ok`. A permission that becomes exercisable
    # is not a validity property of the receipt.
    assert report["ok"] is True


def test_a_successor_declaration_is_reported_as_such(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    out = world["tmp"] / "successor-declaration.json"
    assert (
        cli.main(
            [
                "grant",
                "declare",
                "--publisher",
                PUBLISHER,
                "--artifact",
                RECEIPT_ART,
                "--declared-at",
                DECLARED_AT,
                "--seed",
                str(world["successor_seed"]),
                "--mldsa-seed",
                str(world["successor_mldsa"]),
                "--kid",
                SUCCESSOR_KID,
                "--out",
                str(out),
            ]
        )
        == 0
    )
    capsys.readouterr()

    # The floor grant this world signed names no successors, so the heritage
    # declaration is a stranger's until a widening later version says otherwise.
    view = _write_view(
        world["tmp"],
        grant=json.loads(world["grant"].read_text(encoding="utf-8")),
        declarations=[json.loads(out.read_text(encoding="utf-8"))],
    )
    cli.main(
        [
            "verify",
            str(world["receipt"]),
            "--trust-dir",
            str(world["trust_dir"]),
            "--grant-view",
            str(view),
        ]
    )
    report = _last_json(capsys)

    assert report["grant"] == "dormant"
    assert "grant_declaration_ignored" in report["warnings"]


def test_verify_refuses_a_bare_grant_document_as_the_view(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    """The same reason `--revocations` refuses a lone record: read member by
    member it would resolve to `not_checked`, reporting "no grant evidence" to
    an operator who supplied some."""
    bare = world["tmp"] / "bare.json"
    bare.write_text(world["grant"].read_text(encoding="utf-8"), encoding="utf-8")
    bare_list = world["tmp"] / "bare-list.json"
    bare_list.write_text("[]", encoding="utf-8")

    rc = cli.main(
        [
            "verify",
            str(world["receipt"]),
            "--trust-dir",
            str(world["trust_dir"]),
            "--grant-view",
            str(bare_list),
        ]
    )

    assert rc == 2
    # A bare document IS a JSON object, so it is accepted by the container check
    # and then honestly reports that it carries no grant evidence.
    assert (
        cli.main(
            [
                "verify",
                str(world["receipt"]),
                "--trust-dir",
                str(world["trust_dir"]),
                "--grant-view",
                str(bare),
            ]
        )
        == 0
    )
    assert _last_json(capsys)["grant"] == "not_checked"


# --- the redemption exchange (§18.7, Appendix A) -----------------------------


def test_the_whole_redemption_exchange_runs_from_a_shell(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    challenge = world["tmp"] / "challenge.json"
    response = world["tmp"] / "response.json"

    assert (
        cli.main(
            [
                "grant",
                "challenge",
                "--receipt",
                str(world["receipt"]),
                "--audience",
                CUSTODIAN,
                "--out",
                str(challenge),
            ]
        )
        == 0
    )
    issued = _last_json(capsys)
    assert issued["audience"] == CUSTODIAN
    assert len(keys.b64u_decode(issued["nonce"])) >= 16

    assert (
        cli.main(
            [
                "grant",
                "respond",
                "--challenge",
                str(challenge),
                "--holder-seed",
                str(world["buyer_seed"]),
                "--out",
                str(response),
            ]
        )
        == 0
    )
    capsys.readouterr()

    rc = cli.main(
        [
            "grant",
            "verify",
            "--receipt",
            str(world["receipt"]),
            "--challenge",
            str(challenge),
            "--response",
            str(response),
        ]
    )

    assert rc == 0
    assert _last_json(capsys)["redemption"] == "verified"


def test_each_challenge_carries_a_fresh_nonce(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    """§18.7 requires the nonce be freshly generated by the custodian per
    challenge; a nonce a caller can choose is a nonce a caller can replay,
    which is why there is no flag for it."""
    nonces = set()
    for i in range(3):
        out = world["tmp"] / f"challenge-{i}.json"
        assert (
            cli.main(
                [
                    "grant",
                    "challenge",
                    "--receipt",
                    str(world["receipt"]),
                    "--audience",
                    CUSTODIAN,
                    "--out",
                    str(out),
                ]
            )
            == 0
        )
        nonces.add(_last_json(capsys)["nonce"])

    assert len(nonces) == 3


def test_a_response_produced_for_another_custodian_does_not_verify(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    """`audience` is why §18.7 is a NEW preimage rather than a reuse of v0.1
    §8.2: v0.1's binding challenge names no recipient, so a response produced
    for one custodian would be replayable at another."""
    theirs = world["tmp"] / "theirs.json"
    ours = world["tmp"] / "ours.json"
    response = world["tmp"] / "response.json"
    for path, audience in ((theirs, "other.example"), (ours, CUSTODIAN)):
        assert (
            cli.main(
                [
                    "grant",
                    "challenge",
                    "--receipt",
                    str(world["receipt"]),
                    "--audience",
                    audience,
                    "--out",
                    str(path),
                ]
            )
            == 0
        )
    # The holder answers the OTHER custodian's challenge...
    assert (
        cli.main(
            [
                "grant",
                "respond",
                "--challenge",
                str(theirs),
                "--holder-seed",
                str(world["buyer_seed"]),
                "--out",
                str(response),
            ]
        )
        == 0
    )
    capsys.readouterr()

    # ...and it is replayed at ours.
    rc = cli.main(
        [
            "grant",
            "verify",
            "--receipt",
            str(world["receipt"]),
            "--challenge",
            str(ours),
            "--response",
            str(response),
        ]
    )

    assert rc == 1
    assert _last_json(capsys)["redemption"] == "not_verified"


def test_a_malformed_signature_is_a_refusal_not_a_usage_error(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    """A gate that fronts the delivery of content must not have an error path
    distinguishable from a refusal."""
    challenge = world["tmp"] / "challenge.json"
    assert (
        cli.main(
            [
                "grant",
                "challenge",
                "--receipt",
                str(world["receipt"]),
                "--audience",
                CUSTODIAN,
                "--out",
                str(challenge),
            ]
        )
        == 0
    )
    capsys.readouterr()
    response = world["tmp"] / "junk.json"
    response.write_text(json.dumps({"sig": "not-base64url!!"}), encoding="utf-8")

    rc = cli.main(
        [
            "grant",
            "verify",
            "--receipt",
            str(world["receipt"]),
            "--challenge",
            str(challenge),
            "--response",
            str(response),
        ]
    )

    assert rc == 1
    assert _last_json(capsys)["redemption"] == "not_verified"


def test_a_challenge_naming_another_receipt_is_a_usage_error(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    challenge = world["tmp"] / "challenge.json"
    assert (
        cli.main(
            [
                "grant",
                "challenge",
                "--receipt",
                str(world["receipt"]),
                "--audience",
                CUSTODIAN,
                "--out",
                str(challenge),
            ]
        )
        == 0
    )
    capsys.readouterr()
    tampered = json.loads(challenge.read_text(encoding="utf-8"))
    tampered["receipt_id"] = "01J1V5B4M9Z8QWERTY12345679"
    challenge.write_text(json.dumps(tampered), encoding="utf-8")
    response = world["tmp"] / "response.json"
    response.write_text(json.dumps({"sig": keys.b64u(bytes(64))}), encoding="utf-8")

    assert (
        cli.main(
            [
                "grant",
                "verify",
                "--receipt",
                str(world["receipt"]),
                "--challenge",
                str(challenge),
                "--response",
                str(response),
            ]
        )
        == 2
    )
